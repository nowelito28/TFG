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

// unsigned char K[]; unsigned int K_len=64;
#include "k_embedded.h"


enum {
	BUFSIZE = 100,
	MAX_PROC_SIZE = 1024*20,
	UID_SIZE = 11,
	PID_SIZE = 11,
	PIDNS_SIZE = 15,
	GID_SIZE = 11,
	CMD_SIZE = 50,
	PS_LINE_SIZE = UID_SIZE + PID_SIZE + PIDNS_SIZE + +GID_SIZE + CMD_SIZE,
};


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Noel");


// Referencia a fichero en /proc --> /proc/fddev
static struct proc_dir_entry *ent;


// Separador entre el contenido del fichero y el contenido del kernel:
static const char sep[] = "\n--KERNEL-PS--\n";
static const int sep_len = sizeof(sep) - 1;	// NO contar '\0'


// Separador entre el contenido del kernel y el HMAC en base 64:
static const char sep_hmac[] = "\n--HMAC--\n";
static const int sep_hmac_len = sizeof(sep_hmac) - 1;


// Cabecera para registro de procesos:
static const char header[] = "UID        PID        PID_NS         GID        COMMAND\n";
static const int header_len = sizeof(header) - 1;


// Helper --> Escribir todo el contenido que se pase en f en la posición ppos
// del fichero: Devuelve bytes escritos (off) en éxito <-> <0 en error <-> 0 si
// encuentra EOF
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

// Función aux -> rellenar hasta el final del buffer
static int pad_str_right(char *buf, int curr_len, int buf_len, char pad_char) {
	int padding = 0;

	// Calcular padding
	if (curr_len >= buf_len) {
		padding = 0;
		curr_len = buf_len;

	} else {
		padding = buf_len - curr_len;

	}

	// Aplicar relleno
	if (padding > 0) {
		memset(buf + curr_len, pad_char, padding);
		curr_len += padding;
		
	}

	return buf_len;
}

// Función aux para guardar contenido y avanzar (forma segura)
// Devuelve len bytes guardados (>=0) <-> <0 error
static int safe_chunk(u8 *dst, int *current_len, char *src, int src_len) {
	int max_len = MAX_PROC_SIZE - *current_len;

	if (max_len < src_len) {
		return -ENOSPC;
	}

	// Copiar el contenido
	memcpy(dst + *current_len, src, src_len);

	// Actualizar la longitud escrita
	*current_len += src_len;

	return src_len;
}

// Mapear UID
static int get_uid_str(kuid_t uid_struct, char *uid_str) {
	int uid_len = 0;

	int uid = from_kuid(&init_user_ns, uid_struct);

	if (uid == 0) {
		uid_len = snprintf(uid_str, UID_SIZE, "0/root");

	} else {
		uid_len = snprintf(uid_str, UID_SIZE, "%d", uid);

	}

	pad_str_right(uid_str, uid_len, UID_SIZE, ' ');

	return uid_len;
}

// Mapear PID:
static int get_pid_str(int pid, char *pid_str) {
	int pid_len = snprintf(pid_str, PID_SIZE, "%d", pid);

	pad_str_right(pid_str, pid_len, PID_SIZE, ' ');

	return pid_len;
}

// Mapear PID NS (id único del namespace al que pertenece cada PID):
static int get_pidns_str(struct task_struct *task, char *pidns_str) {
	struct pid_namespace *pid_ns = task->nsproxy->pid_ns_for_children;

	if (!pid_ns) {
		printk(KERN_ERR "get_pidns_str: No PID namespace found for task\n");

		return -ENOSPC;
	}

	int pidns_len = snprintf(pidns_str, PIDNS_SIZE, "%u", pid_ns->ns.inum);

	pad_str_right(pidns_str, pidns_len, PIDNS_SIZE, ' ');

	return pidns_len;
}

// Mapear GID:
static int get_gid_str(struct task_struct *task, char *gid_str) {
	int gid_len = 0;

	// Credenciales seguras del proceso:
	const struct cred *cred = get_task_cred(task);
	if (!cred)
		return -ENOSPC;

	// Obtener el GID y liberar credenciales:
	int gid = from_kgid(&init_user_ns, cred->gid);
	put_cred(cred);

	if (gid == 0) {
		gid_len = snprintf(gid_str, GID_SIZE, "0/root");

	} else {
		gid_len = snprintf(gid_str, GID_SIZE, "%d", gid);

	}

	pad_str_right(gid_str, gid_len, GID_SIZE, ' ');

	return gid_len;
}

// Mapear COMMAND:
static int get_command_str(struct task_struct *task, char *comm_str) {
	int comm_len = 0;

	// Copiar nombre del comando (task->comm) de forma segura:
	// Proceo sin espacio en memoria -> kernel thread:
	if (task->mm == NULL) {
		comm_len = snprintf(comm_str, CMD_SIZE, "[%s]\n", task->comm);

		goto commd_finished;

	}

	// Pocesos user -> ruta completa
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

// Escribir en fichero f (de fd) -> sep_cont + cont + sep_hmac + HMAC
// Devuelve (total) => >0 = bytes escritos totales <-> <0 = error
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

// Calcular el HAMC(SHA-256) con la clave K del contenido que nos pasan:
// Devuelve (rv) => 0 en éxito <-> <0 en error
static int get_hmac_sha256(const u8 *buf, int buf_len, u8 **hmac, int *hmac_len) {
	int rv = 0;

	// Handler Crypto API del kernel -> hash síncrono --> shash (transformador)
	struct crypto_shash *tfm;

	// 1) HAMC(SHA-256) como algoritmo
	// => pide al Crypto API del kernel handler sincrónico (shash) para
	// HMAC-SHA256
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	// 2) Asocia la clave al “transform” (handler)
	rv = crypto_shash_setkey(tfm, K, K_len);
	if (rv)
		goto out_free_tfm;

	// 3) Reservar memoria para el HMAC (calculando su tamaño)
	*hmac_len = crypto_shash_digestsize(tfm);

	*hmac = kmalloc(*hmac_len, GFP_KERNEL);
	if (!*hmac) {
		rv = -ENOMEM;

		goto out_free_tfm;

	}

	// 4) Calcular el HMAC en una sola llamada (one-shot):
	// SHASH_DESC_ON_STACK(desc, tfm) --> macro crea en
	// pila un bloque de memoria del kernel => sizeof(struct shash_desc) +
	// crypto_shash_descsize(tfm) struct shash_desc *desc --> estado
	// intermedio del HMAC mientras se procesa
	// -> Asociamos el algoritmo de HMAC(SHA-256) ->
	// Handler/transformador
	SHASH_DESC_ON_STACK(desc, tfm);
	desc->tfm = tfm;

	// 5) Cálculo final del HMAC => flujo: init -> update -> final en un
	// paso sobre buf (contenido)
	rv = crypto_shash_digest(desc, buf, buf_len, *hmac);

      out_free_tfm:
	crypto_free_shash(tfm);

	return rv;
}

// Calcular HMAC(SHA-256) a Base 64
// Devuelve => 0 en éxito o <0 en error
static int get_hmac_b64(const u8 *hmac, int hmac_len, u8 **hmac_b64,
			int *hmac_b64len) {
	// 1) Calcular espacio de Base64(HMAC):
	int hmac_b64cap = BASE64_CHARS(hmac_len);

	*hmac_b64 = kmalloc(hmac_b64cap, GFP_KERNEL);
	if (!*hmac_b64)
		return -ENOMEM;

	// 2) Codificar HMAC a Base64 y guardar la len real
	*hmac_b64len = base64_encode(hmac, hmac_len, *hmac_b64);
	if (*hmac_b64len < 0) {
		kfree(*hmac_b64);

		return *hmac_b64len;

	}

	return 0;
}

// Info de los procesos de la máquina y guardarla:
// Devuelve 0 éxito <-> 1 error
static int ps_data(struct task_struct *task, u8 *cont, int *cont_len) {
	char uid_str[UID_SIZE];
	char pid_str[PID_SIZE];
	char pidns_str[PIDNS_SIZE];
	char gid_str[GID_SIZE];
	char comm_str[CMD_SIZE];

	// UID:
	int uid_len = get_uid_str(task_uid(task), uid_str);
	if (uid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, uid_str, UID_SIZE) < 0)
		goto out_fail;

	// PID:
	int pid_len = get_pid_str(task_pid_nr(task), pid_str);
	if (pid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, pid_str, PID_SIZE) < 0)
		goto out_fail;

	// PID_NS:
	int pidns_len = get_pidns_str(task, pidns_str);
	if (pidns_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, pidns_str, PIDNS_SIZE) < 0)
		goto out_fail;

	// GID:
	int gid_len = get_gid_str(task, gid_str);
	if (gid_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, gid_str, GID_SIZE) < 0)
		goto out_fail;

	// COMMAND:
	int comm_len = get_command_str(task, comm_str);
	if (comm_len <= 0)
		goto out_fail;

	if (safe_chunk(cont, cont_len, comm_str, comm_len) < 0)
		goto out_fail;

	return 0;

      out_fail:

	return 1;
}

// Obtener información de procesos del kernel para tratarlo como contenido
// Devuelve 0 éxito <-> <0 en error
static int get_ps(u8 **cont, int *cont_len) {
	struct task_struct *task;

	*cont = (u8 *) kmalloc(MAX_PROC_SIZE, GFP_KERNEL);
	if (!*cont) {
		printk(KERN_ERR "get_ps: kmalloc failed\n");

		return -ENOMEM;
	}

	// 1) Copiar la cabecera y actualizar len:
	if (safe_chunk(*cont, cont_len, (char *)header, header_len) < 0)
		goto out_fail;

	// 2) Recorrer todos los procesos del sistema
	// requiere lock de lectura RCU
	rcu_read_lock();

	for_each_process(task) {

		if (*cont_len >= MAX_PROC_SIZE - PS_LINE_SIZE) {
			printk(KERN_WARNING
			       "get_ps: Buffer full -> Truncating\n");

			break;

		}

		if (ps_data(task, *cont, cont_len)) {
			printk(KERN_ERR
			       "get_ps: Extracting process data failed\n");

			rcu_read_unlock();

			goto out_fail;

		}

	}

	rcu_read_unlock();

	printk(KERN_INFO
	       "get_ps: Generated ps-like output of %d bytes.\n", *cont_len);

	return 0;

      out_fail:
	if (*cont)
		kfree(*cont);
	*cont = NULL;
	*cont_len = 0;

	return -ENOSPC;
}

// Función para calcular el HMAC del contenido que queremos poner
// en el fichero dado por 'fd' en mywrite ('f') con HMAC(SHA-256) con clave K
// u8* = unsigned char*
// Devuelve (rv) => >0 = bytes añadidos <=> <0 = error
static int printh(struct file *f) {
	int rv = 0;

	u8 *cont = NULL;
	int cont_len = 0;

	u8 *hmac = NULL;
	int hmac_len = 0;

	u8 *hmac_b64 = NULL;
	int hmac_b64len = 0;

	// 1) Información de procesos desde el kernel (contenido):
	rv = get_ps(&cont, &cont_len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: get_ps failed: %d\n", rv);

		goto out;

	}

	// 2) Calcular (HMAC(SHA 256)) con clave K):
	rv = get_hmac_sha256(cont, cont_len, &hmac, &hmac_len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: generating HMAC failed: %d\n",
		       rv);

		goto out;

	}

	// 3) Pasar el HMAC a Base64:
	rv = get_hmac_b64(hmac, hmac_len, &hmac_b64, &hmac_b64len);
	if (rv < 0) {
		printk(KERN_ERR "Error printH: parsing HMAC to Base 64: %d\n",
		       rv);

		goto out_free_hmac;

	}

	// 4) Escribir contenido y HMAC en el fichero fd 
	// -> sep_cont + cont + sep_hmac + HMAC(base 64):
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

// Validar metadatos del fichero -> inode:
// 1. Verificar modos de escritura y append para el fichero
// 2. Permisos LSM de write y append seguros internos del fichero
// rv --> =0 => OK <-> <0 => -EACCES --> hook de seguridad
// => Evitar condiciones de carrera con el fichero de escritura
static int val_metadata(struct file *f) {
	int rv = 0;

	if (!(f->f_mode & FMODE_WRITE) || !(f->f_flags & O_APPEND)) {
		printk(KERN_ERR "Error printH: fd given must be writable"
		       " and in append mode (O_WRONLY/O_RDWR | O_APPEND)\n");

		return -EBADF;

	}

	rv = file_permission(f, MAY_WRITE | MAY_APPEND);
	if (rv < 0) {
		printk(KERN_ERR
		       "Error printH: permissions VFS/LSM denied: %d\n", rv);

		return rv;

	}

	return rv;
}

// Se ejecuta al escribir en /proc/fddev desde espacio de user
// Escribe contenido del kernel certificado en fd (userpace)
// Devuelve bytes escritos/pos en /proc/fddev (rv) en éxito <-> <0 en error <->
// 0 EOF
static ssize_t mywrite(struct file *file, const char __user *ubuf, size_t count,
		       loff_t *ppos) {
	int fd = 0;
	int rv = 0;
	char buf[BUFSIZE];

	// 1) Ver si es la primera vez que se llama a "write" para este fichero
	// --> sino EOF => single-shot:
	if (*ppos > 0 || count > BUFSIZE) {
		printk(KERN_ERR
		       "/proc/fddev: Only one write allowed or too much bytes "
		       "written (100 bytes max)\n");

		return -EFAULT;

	}

	printk(KERN_DEBUG "/proc/fddev: write handler\n");

	// 2) Copia "count" bytes desde memoria de espacio de user (ubuf) a
	// memoria del kernel (buf) y cambiar puntero de /proc/fddev
	if (copy_from_user(buf, ubuf, count)) {
		printk(KERN_ERR "/proc/fddev: write handler failed\n");

		return -EFAULT;

	}

	rv = strlen(buf);
	printk(KERN_DEBUG "/proc/fddev write: written %d bytes from user\n",
	       rv);
	*ppos = rv;

	// 3) Parsear descriptor de fichero que le pasa el user (fd) a int
	// -> kstrtoint(char[], base, &res)
	if (kstrtoint(buf, 10, &fd)) {
		printk(KERN_ERR
		       "/proc/fddev: can not be parsed fd from userspace\n");

		return -EINVAL;

	}

	// 4) Comprobar que el descriptor de fichero es válido
	if (fd < 0) {
		printk(KERN_ERR "printH: invalid fd (%d)\n", fd);

		return -EBADF;

	}

	// 5) Comprobar que el fd es válido en ESTE proceso
	// para poder referenciarlo al fichero real:
	struct file *f = fget(fd);

	if (!f) {
		printk(KERN_ERR "Error printH: fget failed for fd %d\n", fd);

		return -EBADF;

	}

	// 6) Comprobar metadatos del fichero
	rv = val_metadata(f);
	if (rv < 0)
		goto out_put;

	// 7) Escribir contenido del kernel en f -> HMAC(SHA-256)
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

// Se ejecuta al leer en /proc/fddev desde espacio de user
// Pasarle el contenido guardado en /proc/fddev a userpace
// Devuelve > 0 (bytes leídos -> len) <-> = 0 (EOF) <-> < 0 (error)
static ssize_t myread(struct file *file, char __user *ubuf, size_t count,
		      loff_t *ppos) {
	char buf[] = "Ready to receive file descriptors from user.\n";
	int len = strlen(buf);

	// 1) Ver si primera vez "read" -> sino EOF => single-shot
	if (*ppos > 0 || count < len) {
		printk(KERN_ERR
		       "/proc/fddev: Only one read allowed or very few bytes "
		       "requested\n");

		return 0;

	}

	printk(KERN_DEBUG "/proc/fddev: read handler\n");

	// 2) Copia "len" bytes desde memoria del kernel (buf) a memoria de
	// usuario (ubuf):
	if (copy_to_user(ubuf, buf, len)) {
		printk(KERN_ERR "/proc/fddev: read handler failed\n");

		return -EFAULT;

	}

	// 3) Puntero seguimiento en el último byte copiado
	// en memoria de userspace (len)
	*ppos = len;
	printk(KERN_DEBUG "/proc/fddev myread: read %d bytes by userspace\n",
	       len);

	return len;
}

// Asociar acciones/manejadores para /proc/fddev:
// Utilizar struct proc_ops (en lugar de struct file_operations) a partir del
// kernel 5.6
static const struct proc_ops myops = {
	.proc_read = myread,
	.proc_write = mywrite,
};

// Cargar LKM:
static int init(void) {

	// Crear fichero en /proc -> /proc/fddev:
	ent = proc_create("fddev", 0660, NULL, &myops);
	if (!ent) {
		printk(KERN_ERR "Error creating file in /proc");

		return -ENOMEM;

	}

	printk(KERN_INFO "New proc file created: /proc/fddev\n");

	return 0;
}

// Descargar LKM:
static void cleanup(void) {

	// Borrar referencia al fichero creado en /proc -> /proc/fddev:
	proc_remove(ent);
	printk(KERN_INFO "Proc file deleted: /proc/fddev\n");
}

module_init(init);
module_exit(cleanup);
