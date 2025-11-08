#include <crypto/hash.h>
#include <linux/base64.h>
#include <linux/cred.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/rtc.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

// unsigned char K[]; unsigned int K_len=64;
#include "k_embedded.h"

enum {
  BUFSIZE = 100,
  MAX_PROC_SIZE = 20480,
  UID_SIZE = 11,
  PID_SIZE = 6,
  STAT_SIZE = 7,
  START_SIZE = 8,
  TIME_SIZE = 7,
  CMD_SIZE = 25,
  PS_LINE_SIZE =
      UID_SIZE + PID_SIZE + STAT_SIZE + START_SIZE + TIME_SIZE + CMD_SIZE,
};

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Noel");

// Puntero de referencia/entrada al fichero que crearemos en /proc -->
// /proc/fddev
static struct proc_dir_entry *ent;

// Separador entre el contenido del fichero y el contenido del kernel:
static const char sep[] = "\n--KERNEL-PS-AUX--\n";
static const int sep_len = sizeof(sep) - 1; // NO contar '\0'

// Separador entre el contenido del kernel y el HMAC en base 64:
static const char sep_hmac[] = "\n--HMAC(SHA-256)--\n";
static const int sep_hmac_len = sizeof(sep_hmac) - 1;

// Cabecera para registro de procesos:
static const char header[] = "USER/UID   PID   STAT   START   TIME   COMMAND\n";
static const int header_len = sizeof(header) - 1;

// Helper --> Escribir todo el contenido que se pase en f en la posición ppos
// del fichero: Devuelve bytes escritos (off) en éxito <-> <0 en error <-> 0 si
// encuentra EOF
static int write_full(struct file *f, const char *buf, int len) {
  int w, off = 0;
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

// Convertir int a str de forma segura:
// Devuelve len de la cadena escrita (buf_len - 1 = max dígitos)
// Hecho para buffers pequeños de max 100 bytes
static int int_to_str(int val, char *buf, int buf_len) {
  char temp[BUFSIZE];
  int i = 0;
  int j = 0;
  int len = 0;

  if (buf_len > BUFSIZE)
    return -ENOSPC;

  // Pasar dígitos a cadena de caracteres -> invertido:
  if (val == 0) {
    temp[i++] = '0';

  } else {
    int t = val;

    while (t > 0 && i < (buf_len - 1)) {
      temp[i] = (t % 10) + '0';
      t /= 10;
      i++;
    }
  }

  len = i;

  // Invertir la cadena de dígitos (los hemos puesto al revés) y guardar:
  for (i = len - 1; i >= 0 && j < buf_len; i--) {
    buf[j++] = temp[i];
  }

  return j;
}

// Función aux para guardar contenido y avanzar (forma segura)
// Devuelve len bytes guardados (>=0) <-> <0 error
static int safe_chunk(u8 **dst, int *current_len, char *src, int src_len) {
  int max_len = MAX_PROC_SIZE - *current_len;

  if (max_len < src_len) {
    return -ENOSPC;
  }

  // Copiar el contenido
  memcpy(*dst + *current_len, src, src_len);

  // Actualizar la longitud escrita
  *current_len += src_len;
  return src_len;
}

// Función aux -> mapear UID
// Devuelve UID (str 11 caracts con espacios de relleno)
static char *get_uid_str(kuid_t uid_struct) {
  static char uid_buf[UID_SIZE];
  int uid_len = 0;

  int uid = from_kuid(&init_user_ns, uid_struct);

  // Identificar el root:
  if (uid == 0) {
    uid_buf[uid_len++] = 'r';
    uid_buf[uid_len++] = 'o';
    uid_buf[uid_len++] = 'o';
    uid_buf[uid_len++] = 't';

  } else { // Resto de UIDs -> pasar a UID a str
    uid_len = int_to_str(uid, uid_buf, UID_SIZE);

    if (uid_len < 0)
      return NULL;
  }

  pad_str_right(uid_buf, uid_len, UID_SIZE, ' ');
  return uid_buf;
}

// Función aux para sacar el PID:
static char *get_pid_str(int pid) {
  static char pid_buf[PID_SIZE];
  int pid_len = 0;

  pid_len = int_to_str(pid, pid_buf, PID_SIZE);
  if (pid_len < 0)
    return NULL;

  pad_str_right(pid_buf, pid_len, PID_SIZE, ' ');

  return pid_buf;
}

// Función aux para sacar STAT:
static char *get_stat_str(struct task_struct *task) {
  static char stat_buf[STAT_SIZE];
  int i = 0;

  // Carácter de estado principal:
  stat_buf[i++] = task_state_to_char(task);

  // Flags adicionales:

  // Prioridad alta:
  if (task_nice(task) < 0) {
    stat_buf[i++] = '<';
  }

  // Proceso del kernel:
  if (task->flags & PF_KTHREAD) {
    stat_buf[i++] = 's';
  }

  // Multi-threaded -> Líder de grupo multi-hilo:
  if (thread_group_leader(task) && get_nr_threads(task) > 1) {
    stat_buf[i++] = 'l';
  }

  // Ver si está en foreground de su TTY (del proceso):
  struct signal_struct *sig = READ_ONCE(task->signal);

  if (sig) {
    struct tty_struct *tty = rcu_dereference(sig->tty);

    if (tty) {
      struct pid *pg = tty_get_pgrp(tty); // Ref del grupo (GID)
      pid_t pgrp_nr = 0;

      if (pg) {
        pgrp_nr = pid_nr(pg);
        put_pid(pg);
      }

      if (pgrp_nr == task_pgrp_nr(task))
        stat_buf[i++] = '+';
    }
  }

  pad_str_right(stat_buf, i, STAT_SIZE, ' ');

  return stat_buf;
}

// Función aux para sacar START -> HH:MM (5 chars + 3 espacios):
static char *get_start_str(struct task_struct *task) {
  static char start_buf[START_SIZE];
  int i = 0;

  struct timespec64 start_time_ts;
  struct tm start_time_tm;

  // 1. Tiempo de inicio absoluto
  // (Quitar segs desde boot y sumar segs de jiffies):
  ktime_get_real_ts64(&start_time_ts);
  start_time_ts.tv_sec -= (ktime_get_ns() / NSEC_PER_SEC);
  start_time_ts.tv_sec += (task->start_time / HZ);

  // 2. Convertir a estructura tm (hora del día):
  time64_to_tm(start_time_ts.tv_sec, 0, &start_time_tm);

  // 3. Guardar HH:MM (5 chars + 3 espacios):
  // Horas (HH)
  start_buf[i] = (start_time_tm.tm_hour / 10) + '0';
  start_buf[i++] = (start_time_tm.tm_hour % 10) + '0';
  // Separador
  start_buf[i++] = ':';
  // Mins (MM)
  start_buf[i++] = (start_time_tm.tm_min / 10) + '0';
  start_buf[i++] = (start_time_tm.tm_min % 10) + '0';

  pad_str_right(start_buf, i, START_SIZE, ' ');

  return start_buf;
}

// Función aux para sacar TIME -> Tiempo de CPU HH:MM (5 chars + 2 espacios):
static char *get_time_str(struct task_struct *task) {
  static char time_buf[TIME_SIZE];
  int i = 0;

  // 1. Tiempo total de CPU:
  unsigned long time_jiffies = task->utime + task->stime;

  // 2. Convertir a segundos:
  long secs_running = jiffies_to_msecs(time_jiffies) / 1000;

  int mins = secs_running / 60;
  int secs = secs_running % 60;

  // 3. Guardar MM:SS (5 chars + 2 espacios):
  // Mins (MM)
  time_buf[i] = (mins / 10) + '0';
  time_buf[i++] = (mins % 10) + '0';
  // Separador
  time_buf[i++] = ':';
  // Segs (SS)
  time_buf[i++] = (secs / 10) + '0';
  time_buf[i++] = (secs % 10) + '0';

  pad_str_right(time_buf, i, TIME_SIZE, ' ');

  return time_buf;
}

// Función aux para sacar el COMMAND (24 chars max + \n):
static char *get_command_str(struct task_struct *task, int *len) {
  static char comm_buf[CMD_SIZE];
  int i = 0;

  // Copiar nombre del comando (task->comm) de forma segura:
  int comm_len = strnlen(task->comm, TASK_COMM_LEN);

  if (comm_len >= CMD_SIZE - 1)
    comm_len = CMD_SIZE - 1;

  memcpy(comm_buf + i, task->comm, comm_len);
  i += comm_len;

  comm_buf[i++] = '\n';
  *len = i;

  return comm_buf;
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
static int get_hmac_sha256(const u8 *buf, int buf_len, u8 **hmac,
                           int *hmac_len) {
  int rv = 0;

  // Handler del Crypto API del kernel para un hash síncrono --> shash =>
  // Transformador:
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
  // SHASH_DESC_ON_STACK(desc, tfm) --> macro (<crypto/hash.h>) crea en la pila
  // un bloque de memoria del kernel => sizeof(struct shash_desc) +
  // crypto_shash_descsize(tfm) struct shash_desc *desc --> estado intermedio
  // del HMAC mientras se procesa
  // -> Le asociamos el algoritmo de HMAC(SHA-256) -> Handler/transformador
  SHASH_DESC_ON_STACK(desc, tfm);
  desc->tfm = tfm;

  // 5) Cálculo final del HMAC => flujo: init -> update -> final en un paso
  // sobre buf (contenido)
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

  // 2) Codificar el HMAC a Base64 y guardar la longitud real escrita en b64len
  *hmac_b64len = base64_encode(hmac, hmac_len, *hmac_b64);
  if (*hmac_b64len < 0) {
    kfree(*hmac_b64);
    return *hmac_b64len;
  }

  return 0;
}

// Info de los procesos de la máquina y guardarla:
// Devuelve 0 éxito <-> 1 en error
static int ps_data(struct task_struct *task, u8 **cont, int *cont_len) {

  // USER -> UID:
  char *uid_str = get_uid_str(task_uid(task));
  if (!uid_str)
    goto out_fail;
  if (safe_chunk(cont, cont_len, uid_str, UID_SIZE) < 0)
    goto out_fail;

  // PID:
  char *pid_str = get_pid_str(task_pid_nr(task));
  if (!pid_str)
    goto out_fail;
  if (safe_chunk(cont, cont_len, pid_str, PID_SIZE) < 0)
    goto out_fail;

  // STAT:
  char *stat_str = get_stat_str(task);
  if (!stat_str)
    goto out_fail;
  if (safe_chunk(cont, cont_len, stat_str, STAT_SIZE) < 0)
    goto out_fail;

  // START:
  char *start_str = get_start_str(task);
  if (safe_chunk(cont, cont_len, start_str, START_SIZE) < 0)
    goto out_fail;

  // TIME:
  char *time_str = get_time_str(task);
  if (safe_chunk(cont, cont_len, time_str, TIME_SIZE) < 0)
    goto out_fail;

  // COMMAND:
  int comm_len = 0;
  char *command_str = get_command_str(task, &comm_len);
  if (safe_chunk(cont, cont_len, command_str, comm_len) < 0)
    goto out_fail;

  return 0;

out_fail:
  return 1;
}

// Obtener información de procesos del kernel para tratarlo como contenido
// Devuelve 0 éxito <-> <0 en error
static int get_ps_aux(u8 **cont, int *cont_len) {
  struct task_struct *task;

  *cont = (u8 *)kmalloc(MAX_PROC_SIZE, GFP_KERNEL);
  if (!*cont)
    return -ENOMEM;

  // 1) Copiar la cabecera y actualizar len:
  if (safe_chunk(cont, cont_len, (char *)header, header_len) < 0)
    goto out_fail;

  // 2) Recorrer todos los procesos del sistema
  // requiere lock de lectura RCU
  rcu_read_lock();
  for_each_process(task) {

    if (*cont_len >= MAX_PROC_SIZE - PS_LINE_SIZE) {
      printk(KERN_WARNING
             "get_ps_aux: Process buffer full -> Truncating ps output\n");
      break;
    }

    if (ps_data(task, cont, cont_len)) {
      printk(KERN_ERR "get_ps_aux: Extracting process data failed\n");
      goto out_fail;
    }
  }
  rcu_read_unlock();

  printk(KERN_INFO "get_ps_aux: Generated ps_aux-like output of %d bytes.\n",
         *cont_len);
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
  rv = get_ps_aux(&cont, &cont_len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: get_ps_aux_from_kernel failed: %d\n", rv);
    goto out;
  }

  // 2) Calcular (HMAC(SHA 256)) con clave K):
  rv = get_hmac_sha256(cont, cont_len, &hmac, &hmac_len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: generating HMAC failed: %d\n", rv);
    goto out;
  }

  // 3) Pasar el HMAC a Base64:
  rv = get_hmac_b64(hmac, hmac_len, &hmac_b64, &hmac_b64len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: parsing HMAC to Base 64: %d\n", rv);
    goto out_free_hmac;
  }

  // 4) Escribir contenido y HMAC en el fichero fd -> sep_cont + cont + sep_hmac
  // + HMAC(base 64):
  rv = write_cont_hmac(f, cont, cont_len, hmac_b64, hmac_b64len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: writing content: %d\n", rv);
    goto out_free_hmacs;
  }
  printk(KERN_INFO "printH: file has been written with content certificated by "
                   "HMAC(SHA-256)\n");

out_free_hmacs:
  kfree(hmac_b64);
out_free_hmac:
  kfree(hmac);
out:
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
    printk(KERN_ERR
           "Error printH: fd given must be writable (O_WRONLY/O_RDWR)\n");
    return -EBADF;
  }

  rv = file_permission(f, MAY_WRITE | MAY_APPEND);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: permissions VFS/LSM denied: %d\n", rv);
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
  int fd, rv = 0;
  char buf[BUFSIZE];

  // 1) Ver si es la primera vez que se llama a "write" para este fichero -->
  // sino EOF => single-shot:
  if (*ppos > 0 || count > BUFSIZE) {
    printk(KERN_ERR "/proc/fddev: Only one write allowed or too much bytes "
                    "sent (100 bytes max)\n");
    return -EFAULT;
  }
  printk(KERN_DEBUG "/proc/fddev: write handler\n");

  // 2) Copia "count" bytes desde memoria de espacio de user (ubuf) a memoria
  // del kernel (buf) y cambiar puntero de seguimiento del fichero /proc/fddev:
  if (copy_from_user(buf, ubuf, count)) {
    printk(KERN_ERR "/proc/fddev: write handler failed\n");
    return -EFAULT;
  }

  rv = strlen(buf);
  printk(KERN_DEBUG "/proc/fddev write: written %d bytes from the user\n", rv);
  *ppos = rv;

  // 3) Parsear descriptor de fichero que le pasa el user (fd) a int
  // -> kstrtoint(char[], base, &res)
  if (kstrtoint(buf, 10, &fd)) {
    printk(KERN_ERR "/proc/fddev: can not be parsed fd from userspace\n");
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
  if (rv < 0) {
    goto out_put;
  }

  // 7) Escribir contenido del kernel certificado en fd -> HMAC(SHA-256) con
  // clave K embebida:
  rv = printh(f);
  if (rv < 0) {
    printk(KERN_ERR "Error mywrite: printH failed for fd %d: %d\n", fd, rv);
    goto out_put;
  }
  printk(KERN_DEBUG "mywrite: printH OK for fd %d (%d bytes written)\n", fd,
         rv);

out_put:
  fput(f);
  return rv;
}

// Se ejecuta al leer en /proc/fddev desde espacio de user
// Pasarle el contenido guardado en /proc/fddev a userpace
// Devuelve > 0 (bytes leídos -> len) <-> = 0 (EOF) <-> < 0 (error)
static ssize_t myread(struct file *file, char __user *ubuf, size_t count,
                      loff_t *ppos) {
  char buf[] = "LKM ready to receive file descriptors from user.";
  int len = strlen(buf);

  // 1) Ver si es la primera vez que se llama a "read" para este fichero -->
  // sino EOF => single-shot
  if (*ppos > 0 || count < len) {
    printk(KERN_ERR
           "/proc/fddev: Only one read allowed or very few bytes requested\n");
    return 0;
  }
  printk(KERN_DEBUG "/proc/fddev: read handler\n");

  // 2) Copia "len" bytes desde memoria del kernel (buf) a memoria de usuario
  // (ubuf):
  if (copy_to_user(ubuf, buf, len)) {
    printk(KERN_ERR "/proc/fddev: read handler failed\n");
    return -EFAULT;
  }

  // 3) Puntero seguimiento (*ppos) del fichero en el último byte copiado en
  // memoria de userspace (len)
  *ppos = len;
  printk(KERN_DEBUG "/proc/fddev myread: read %d bytes by userspace\n", len);

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
static int simple_init(void) {
  // 1) Imprime K en hexadecimal en los logs del kernel (/var/log/kern.log)
  // -> %*phC separa bytes con ':' => SOLO EN PRUEBAS
  printk(KERN_DEBUG "K (64Bytes) loaded = %*phC\n", K_len, K);

  // 2) Crear fichero en /proc -> /proc/fddev:
  ent = proc_create("fddev", 0660, NULL, &myops);
  if (!ent) {
    printk(KERN_ERR "Error creating file in /proc");
    return -ENOMEM;
  }
  printk(KERN_INFO "New proc file created: /proc/fddev\n");

  return 0;
}

// Descargar LKM:
static void simple_cleanup(void) {
  // 1) Borrar referencia al fichero creado en /proc -> /proc/fddev:
  proc_remove(ent);
  printk(KERN_INFO "Proc file deleted: /proc/fddev\n");
}

module_init(simple_init);
module_exit(simple_cleanup);
