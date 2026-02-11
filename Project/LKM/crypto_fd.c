#include <crypto/hash.h>
#include <linux/base64.h>
#include <linux/cred.h>
#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

// unsigned char K[]; unsigned int K_len=64;
#include "k_embedded.h"


enum {
	BUFSIZE = 100,
	MAX_PROC_SIZE = 1024*40,
	TIPIC_HMACB64_SIZE = 44,
	UID_SIZE = 12,
	UIDNS_SIZE = 14,
	PID_SIZE = 12,
	PIDNS_SIZE = 14,
	GID_SIZE = 11,
	CMD_SIZE = 50,
	PS_LINE_SIZE = UID_SIZE + UID_SIZE + UIDNS_SIZE + 
		       PID_SIZE + PID_SIZE + PIDNS_SIZE + GID_SIZE + CMD_SIZE,
};


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Noel");


// /proc file reference --> /proc/fddev
static struct proc_dir_entry *ent;


// Separator between file content and kernel content:
static const char sep[] = "\n--KERNEL-PS--\n";
static const int sep_len = sizeof(sep) - 1;	// Do not take into account with '\0'


// Separator between kernel content and Base64 HMAC:
static const char sep_hmac[] = "\n--HMAC--\n";
static const int sep_hmac_len = sizeof(sep_hmac) - 1;


// Processes metadata headers:
static const char header[] = "UID_KERNEL  UID_LOCAL   UID_NS        PID_KERNEL  PID_LOCAL   PID_NS        GID        COMMAND\n";
static const int header_len = sizeof(header) - 1;


// Aux function -> Write all content passed in buf to the file position ppos:
// Return: bytes written (off) success <-> <0 error <-> 0 if EOF is found
static int write_full(struct file *f, const char *buf, int len) {
	int w = 0;
	int off = 0;
	loff_t *ppos = &f->f_pos;

	while (off < len) {
		w = kernel_write(f, buf + off, len - off, ppos);

		if (w < 0)
			return w;

		if (w == 0)
			return -EIO;

		off += w;

	}

	return off;
}

// Aux function -> fill the buffer with padding characters:
// Return: total length of the string after padding (>=0) <-> <0 error
static int pad_str_right(char *buf, int curr_len, int buf_len, char pad_char) {
	int padding = 0;

	if (curr_len >= buf_len) {
		padding = 0;
		curr_len = buf_len;

	} else {
		padding = buf_len - curr_len;

	}

	if (padding > 0) {
		memset(buf + curr_len, pad_char, padding);
		curr_len += padding;
		
	}

	return buf_len;
}

// Aux function -> secure method to store content without aliasing and overflow issues:
// Return: len bytes saved (>=0) <-> <0 error
static int safe_chunk(u8 *dst, int *current_len, char *src, int src_len) {
	int max_len = MAX_PROC_SIZE - *current_len;

	if (max_len < src_len)
		return -ENOSPC;

	memcpy(dst + *current_len, src, src_len);

	*current_len += src_len;

	return src_len;
}

// Map general UID (from kernel):
static int get_kuid_str(kuid_t uid_struct, char *uid_str) {
	int uid_len = 0;

	int uid = from_kuid(&init_user_ns, uid_struct);

	uid_len = snprintf(uid_str, UID_SIZE, "%d", uid);

	pad_str_right(uid_str, uid_len, UID_SIZE, ' ');

	return uid_len;
}

// Map local UID (relative to the process's namespace):
static int get_luid_str(struct task_struct *task, char *uid_str) {
	int uid_len = 0;

	const struct cred *cred = get_task_cred(task);
	if (!cred){
		printk(KERN_ERR "get_luid_str: No credentials found for task\n");

		return -ENOSPC;

	}

	int uid = from_kuid(cred->user_ns, cred->uid);

	put_cred(cred);

	uid_len = snprintf(uid_str, UID_SIZE, "%d", uid);

	pad_str_right(uid_str, uid_len, UID_SIZE, ' ');

	return uid_len;
}

// Map UID NS (unique id of each namespace where belongs every UID):
static int get_uidns_str(struct task_struct *task, char *uidns_str) {
	const struct cred *cred = get_task_cred(task);
	if (!cred) {
		printk(KERN_ERR "get_uidns_str: No credentials found for task\n");

		return -ENOSPC;

	}

	unsigned int uid_ns = cred->user_ns->ns.inum;

	put_cred(cred);

	int uidns_len = snprintf(uidns_str, UIDNS_SIZE, "%u", uid_ns);

	pad_str_right(uidns_str, uidns_len, UIDNS_SIZE, ' ');

	return uidns_len;
}

// Map general PID (from kernel):
static int get_kpid_str(int pid, char *pid_str) {
	int pid_len = snprintf(pid_str, PID_SIZE, "%d", pid);

	pad_str_right(pid_str, pid_len, PID_SIZE, ' ');

	return pid_len;
}

// Map local PID (relative to the process's namespace):
static int get_lpid_str(struct task_struct *task, char *pid_str) {
        struct pid_namespace *ns = task_active_pid_ns(task);
        if (!ns) {
		printk(KERN_ERR "get_lpid_str: No PID namespace found for task\n");

             	return -ENOSPC;

        }

        int pid = task_pid_nr_ns(task, ns);

        int pid_len = snprintf(pid_str, PID_SIZE, "%d", pid);

        pad_str_right(pid_str, pid_len, PID_SIZE, ' ');

        return pid_len;
}

// Map PID NS (unique id of each namespace where belongs every PID):
static int get_pidns_str(struct task_struct *task, char *pidns_str) {
	struct pid_namespace *pid_ns = task_active_pid_ns(task);
	if (!pid_ns) {
		printk(KERN_ERR "get_pidns_str: No PID namespace found for task\n");

		return -ENOSPC;
	}

	int pidns_len = snprintf(pidns_str, PIDNS_SIZE, "%u", pid_ns->ns.inum);

	pad_str_right(pidns_str, pidns_len, PIDNS_SIZE, ' ');

	return pidns_len;
}

// Map GID:
static int get_gid_str(struct task_struct *task, char *gid_str) {
	int gid_len = 0;

	const struct cred *cred = get_task_cred(task);
	if (!cred)
		return -ENOSPC;

	int gid = from_kgid(&init_user_ns, cred->gid);
	put_cred(cred);

	gid_len = snprintf(gid_str, GID_SIZE, "%d", gid);

	pad_str_right(gid_str, gid_len, GID_SIZE, ' ');

	return gid_len;
}

// Map COMMAND -> print each command/executable safetly (task->comm):
static int get_command_str(struct task_struct *task, char *comm_str) {
	int comm_len = 0;

	// Process without memory space -> kernel thread:
	if (task->mm == NULL) {
		comm_len = snprintf(comm_str, CMD_SIZE, "[%s]\n", task->comm);

		goto commd_finished;

	}

	// User process -> full path:
	struct file *exe_file = task->mm->exe_file;

	if (exe_file) {
		char *path = d_path(&exe_file->f_path, comm_str, CMD_SIZE);

		if (!IS_ERR(path)) {
			comm_len = snprintf(comm_str, CMD_SIZE, "%s\n", path);

			goto commd_finished;

		}
	}

	comm_len = snprintf(comm_str, CMD_SIZE, "%s\n", task->comm);


      commd_finished:
	if (comm_len >= CMD_SIZE)
		comm_len = CMD_SIZE - 1;

	return comm_len;
}

// Write in file f (from fd) -> sep_cont + cont + sep_hmac + HMAC
// Return: total bytes written (>=0) <-> <0 error
static int write_cont_hmac(struct file *f, const char *cont, int cont_len,
			   const char *hmac_b64, int hmac_b64len) {
	int w = 0;
	int total = 0;

	w = write_full(f, sep, sep_len);
	if (w < 0)
		return w;

	total += w;

	w = write_full(f, cont, cont_len);
	if (w < 0)
		return w;

	total += w;

	w = write_full(f, sep_hmac, sep_hmac_len);
	if (w < 0)
		return w;

	total += w;

	w = write_full(f, hmac_b64, hmac_b64len);
	if (w < 0)
		return w;

	total += w;

	return total;
}

// Calculate HAMC(SHA-256) with K (key embedded) of the content :
// Return: rv (=>0) <-> <0 error
static int get_hmac_sha256(const u8 *buf, int buf_len, u8 **hmac, int *hmac_len) {
	int rv = 0;

	// Kernel handler Crypto API -> synchronous hash --> shash (transformer)
	struct crypto_shash *tfm;

	// 1) HAMC(SHA-256) as symmetrical algorithm:
	// ask Crypto API handler for the shash for HMAC-SHA256
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	// 2) Get K key associated to the “transformer” (handler):
	rv = crypto_shash_setkey(tfm, K, K_len);
	if (rv)
		goto out_free_tfm;

	// 3) Reserve memory for the HMAC (calculating its size)
	*hmac_len = crypto_shash_digestsize(tfm);

	*hmac = kmalloc(*hmac_len, GFP_KERNEL);
	if (!*hmac) {
		rv = -ENOMEM;

		goto out_free_tfm;

	}

	// 4) Calculate the HMAC in one single call (one-shot):
	// -> SHASH_DESC_ON_STACK(desc, tfm) --> macro create in stack a kernel memory block
	// -> sizeof(struct shash_desc) + crypto_shash_descsize(tfm) struct shash_desc *desc
	// --> middle HMAC state while its processing
	// -> Associate HMAC(SHA-256) algorithm --> Handler/transformer
	SHASH_DESC_ON_STACK(desc, tfm);
	desc->tfm = tfm;

	// 5) Final HMAC calculation:
	// execution flow: init -> update -> final => in one single call over buf(content)
	rv = crypto_shash_digest(desc, buf, buf_len, *hmac);

      out_free_tfm:
	crypto_free_shash(tfm);

	return rv;
}

// Calculate HMAC(SHA-256) to Base64
// Return: =>0 <-> <0 error
static int get_hmac_b64(const u8 *hmac, int hmac_len, u8 **hmac_b64,
			int *hmac_b64len) {
	// 1) Calculate needed for Base64(HMAC):
	int hmac_b64cap = BASE64_CHARS(hmac_len);

	*hmac_b64 = kmalloc(hmac_b64cap, GFP_KERNEL);
	if (!*hmac_b64)
		return -ENOMEM;

	// 2) Encode HMAC to Base64 and save its real length:
	*hmac_b64len = base64_encode(hmac, hmac_len, *hmac_b64);
	if (*hmac_b64len < 0) {
		kfree(*hmac_b64);

		return *hmac_b64len;

	}

	return 0;
}

// Processes metadata registered in the machine and save it:
// Return: 0 success <-> 1 error
static int ps_data(struct task_struct *task, u8 *cont, int *cont_len) {
	char kuid_str[UID_SIZE];
	char luid_str[UID_SIZE];
	char uidns_str[UIDNS_SIZE];
	char kpid_str[PID_SIZE];
	char lpid_str[PID_SIZE];
	char pidns_str[PIDNS_SIZE];
	char gid_str[GID_SIZE];
	char comm_str[CMD_SIZE];

	// general UID (from kernel):
	int kuid_len = get_kuid_str(task_uid(task), kuid_str);
	if (kuid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, kuid_str, UID_SIZE) < 0)
		goto out_fail;

	// local UID (related to the process's namespace):
	int luid_len = get_luid_str(task, luid_str);
	if (luid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, luid_str, UID_SIZE) < 0)
		goto out_fail;

	// UID Namespace:
	int uidns_len = get_uidns_str(task, uidns_str);
	if (uidns_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, uidns_str, UIDNS_SIZE) < 0)
		goto out_fail;

	// general PID (from kernel):
	int kpid_len = get_kpid_str(task_pid_nr(task), kpid_str);
	if (kpid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, kpid_str, PID_SIZE) < 0)
		goto out_fail;

	// local PID (related to the process's namespace):
	int lpid_len = get_lpid_str(task, lpid_str);
	if (lpid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, lpid_str, PID_SIZE) < 0)
		goto out_fail;

	// PID Namespace:
	int pidns_len = get_pidns_str(task, pidns_str);
	if (pidns_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, pidns_str, PIDNS_SIZE) < 0)
		goto out_fail;

	// GID (group id of the process):
	int gid_len = get_gid_str(task, gid_str);
	if (gid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, gid_str, GID_SIZE) < 0)
		goto out_fail;

	// COMMAND (executable name/path of the process):
	int comm_len = get_command_str(task, comm_str);
	if (comm_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, comm_str, comm_len) < 0)
		goto out_fail;

	return 0;

      out_fail:

	return 1;
}

// Get info from current processes running in the system = content
// Return: 0 success <-> <0 error
static int get_ps(u8 **cont, int *cont_len) {
	struct task_struct *task;

	*cont = (u8 *) kmalloc(MAX_PROC_SIZE, GFP_KERNEL);
	if (!*cont) {
		printk(KERN_ERR "get_ps: kmalloc failed\n");

		return -ENOMEM;
	}

	// 1) Copy the header and update len:
	if (safe_chunk(*cont, cont_len, (char *)header, header_len) < 0)
		goto out_fail;

	// 2) Go through the list of processes running:
	// requires read RCU lock
	rcu_read_lock();

	for_each_process(task) {

		if (*cont_len >= MAX_PROC_SIZE - PS_LINE_SIZE - 
			sep_len - sep_hmac_len - TIPIC_HMACB64_SIZE) {
			printk(KERN_WARNING
			       "get_ps: Buffer full -> Truncating\n");

			goto out_fail;

		}

		if (ps_data(task, *cont, cont_len)) {
			printk(KERN_ERR
			       "get_ps: Extracting process data failed\n");

			goto out_fail;

		}

	}

	rcu_read_unlock();

	printk(KERN_INFO
	       "get_ps: Generated ps-like output of %d bytes.\n", *cont_len);

	return 0;

      out_fail:
	rcu_read_unlock();

	if (*cont)
		kfree(*cont);
	*cont = NULL;
	*cont_len = 0;

	return -ENOSPC;
}

// Write the process list and its HMAC 
// to the file associated with the provided fd:
// Return: rv=bytes added (=>0) <-> <0 error
static int printh(struct file *f) {
	int rv = 0;

	// u8* = unsigned char*
	u8 *cont = NULL;
	int cont_len = 0;

	u8 *hmac = NULL;
	int hmac_len = 0;

	u8 *hmac_b64 = NULL;
	int hmac_b64len = 0;

	// 1) Content -> Get info from current processes running in the system:
	rv = get_ps(&cont, &cont_len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: get_ps failed: %d\n", rv);

		goto out;

	}

	// 2) Calculate HMAC(SHA 256) with K (key embedded):
	rv = get_hmac_sha256(cont, cont_len, &hmac, &hmac_len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: generating HMAC failed: %d\n",
		       rv);

		goto out;

	}

	// 3) Parse HMAC to Base64:
	rv = get_hmac_b64(hmac, hmac_len, &hmac_b64, &hmac_b64len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: parsing HMAC to Base 64: %d\n",
		       rv);

		goto out_free_hmac;

	}

	// 4) Write all the content in the file given:
	// -> sep_cont + cont + sep_hmac + HMAC(Base64):
	rv = write_cont_hmac(f, cont, cont_len, hmac_b64, hmac_b64len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: writing content: %d\n", rv);

		goto out_free_hmacs;

	}

	printk(KERN_INFO
	       "printH: file has been written with HAMC \n");

      out_free_hmacs:
	kfree(hmac_b64);

      out_free_hmac:
	kfree(hmac);

      out:
	if (cont)
		kfree(cont);

	return rv;
}

// Validate file metadata -> inode:
// Avoid race conditions with the write file pointer (ppos)
// Return: rv (=0) success <-> <0 -EACCES --> security hook
static int val_metadata(struct file *f) {
	int rv = 0;

	// Verify write and append modes:
	if (!(f->f_mode & FMODE_WRITE) || !(f->f_flags & O_APPEND)) {
		printk(KERN_ERR "Error printH: fd given must be writable"
		       " and in append mode (O_WRONLY/O_RDWR | O_APPEND)\n");

		return -EBADF;

	}

	// Verify LSM permissions for write and append:
	rv = file_permission(f, MAY_WRITE | MAY_APPEND);
	if (rv < 0) {
		printk(KERN_ERR
		       "Error printH: permissions VFS/LSM denied: %d\n", rv);

	}

	return rv;
}

// Executed when writing in /proc/fddev from userspace:
// Write the content of the kernel in the file given by fd (userpace) in mywrite ('f'):
// Return: rv=bytes added (>0) <-> <0 error <-> 0 EOF
static ssize_t mywrite(struct file *file, const char __user *ubuf, size_t count,
		       loff_t *ppos) {
	int fd = 0;
	int rv = 0;
	char buf[BUFSIZE];

	// 1)  Single-shot => Verify only one write allowed at the same time (ppos)
	// and max bytes allowed (BUFSIZE)
	if (*ppos > 0 || count > BUFSIZE) {
		printk(KERN_ERR
		       "/proc/fddev: Only one write allowed or too much bytes "
		       "written (%d bytes max)\n", BUFSIZE);

		return -EFAULT;

	}

	printk(KERN_DEBUG "/proc/fddev: write handler\n");

	// 2) Copy "count" bytes from userspace memory (ubuf)
	// to kernel memory (buf) count bytes and 
	// update the write file position pointer (ppos) in /proc/fddev:
	if (copy_from_user(buf, ubuf, count)) {
		printk(KERN_ERR "/proc/fddev: write handler failed\n");

		return -EFAULT;

	}

	rv = strlen(buf);
	printk(KERN_DEBUG "/proc/fddev write: written %d bytes from user\n",
	       rv);
	*ppos = rv;

	// 3) Parse file descriptor given from userspace to int:
	// kstrtoint(char[], base, &res)
	if (kstrtoint(buf, 10, &fd)) {
		printk(KERN_ERR
		       "/proc/fddev: could not parse fd from userspace\n");

		return -EINVAL;

	}

	// 4) Check if fd is valid:
	if (fd < 0) {
		printk(KERN_ERR "printH: invalid fd (%d)\n", fd);

		return -EBADF;

	}

	// 5) Check if fd is valid for this process to refer it from the real one:
	struct file *f = fget(fd);

	if (!f) {
		printk(KERN_ERR "Error printH: fget failed for fd %d\n", fd);

		return -EBADF;

	}

	// 6) Check file metadata:
	rv = val_metadata(f);
	if (rv < 0)
		goto out_put;

	// 7) Write kernel content in f:
	rv = printh(f);
	if (rv < 0) {
		printk(KERN_ERR "Error mywrite: printH failed for fd %d: %d\n",
		       fd, rv);

		goto out_put;

	}

	printk(KERN_DEBUG "mywrite: printH OK for fd %d (%d bytes written)\n",
	       fd, rv);

      out_put:
	fput(f);

	return rv;
}

// Executed when reading in /proc/fddev from userspace:
// Give content save in kernel memory in /proc/fddev to user spaceace
// Return: rv=bytes read (>0) <-> <0 error <-> 0 EOF
static ssize_t myread(struct file *file, char __user *ubuf, size_t count,
		      loff_t *ppos) {
	char buf[] = "Ready to receive file descriptors from user.\n";
	int len = strlen(buf);

	// 1)  Single-shot => Verify only one read allowed at the same time (ppos)
	// and max bytes allowed requested (len)
	if (*ppos > 0 || count < len) {
		printk(KERN_ERR
		       "/proc/fddev: Only one read allowed or very few bytes "
		       "requested\n");

		return 0;

	}

	printk(KERN_DEBUG "/proc/fddev: read handler\n");

	// 2) Copy "count" bytes from kernel memory (kbuf)
	// to userspace memory (ubuf) len bytes 
	// and update the read file position pointer (ppos) in /proc/fddev:
	if (copy_to_user(ubuf, buf, len)) {
		printk(KERN_ERR "/proc/fddev: read handler failed\n");

		return -EFAULT;

	}

	// 3) Keeping pointer in the last byte copied in userspace memory (len):
	*ppos = len;
	printk(KERN_DEBUG "/proc/fddev myread: read %d bytes by userspace\n",
	       len);

	return len;
}

// Associate handlers for /proc/fddev:
// Use struct proc_ops (instead of struct file_operations)
// from kernel 5.6
static const struct proc_ops myops = {
	.proc_read = myread,
	.proc_write = mywrite,
};

// Load LKM:
static int init(void) {

	// Create file in /proc -> /proc/fddev:
	ent = proc_create("fddev", 0660, NULL, &myops);
	if (!ent) {
		printk(KERN_ERR "Error creating file in /proc");

		return -ENOMEM;

	}

	printk(KERN_INFO "New proc file created: /proc/fddev\n");

	return 0;
}

// Download LKM:
static void cleanup(void) {

	// Remove any reference to the file created in /proc -> /proc/fddev:
	proc_remove(ent);
	printk(KERN_INFO "Proc file deleted: /proc/fddev\n");
}

module_init(init);
module_exit(cleanup);
