#include <crypto/hash.h>
#include <linux/base64.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/security.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>

// unsigned char K[]; unsigned int K_len=64;
#include "k_embedded.h"

enum { BUFSIZE = 100 };

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Noel");

// Puntero de referencia/entrada al fichero que crearemos en /proc -->
// /proc/fddev
static struct proc_dir_entry *ent;

// Separador textual entre el contenido y el HMAC en base 64:
static const char sep[] = "\n-HMAC(SHA-256)-\n";
static const char sep_len = sizeof(sep) - 1; // NO contar '\0'

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

// Escribir en fichero f (de fd) -> cont + sep + HMAC
// Devuelve (total) => >0 = bytes escritos totales <-> <0 = error
static int write_cont_hmac(struct file *f, const char *cont, int cont_len,
                           const char *hmac_b64, int hmac_b64len) {
  int w, total = 0;

  w = write_full(f, cont, cont_len);
  if (w < 0)
    return w;
  total += w;

  w = write_full(f, sep, sep_len);
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

// Función para calcular el HMAC del contenido que queremos poner
// en el fichero dado por 'fd' en mywrite ('f') con HMAC(SHA-256) con clave K
// Devuelve (rv) => >0 = bytes añadidos <=> <0 = error
static int printh(struct file *f) {
  int rv = 0;

  const char cont[] =
      "\nThis is an authentic content to be validated by HMAC(SHA-256)!!\n";
  const int cont_len = sizeof(cont) - 1; // NO contar '\0'

  u8 *hmac = NULL; // u8* = unsigned char*
  int hmac_len = 0;

  u8 *hmac_b64 = NULL;
  int hmac_b64len = 0;

  // 1) Calcular (HMAC(SHA 256)) con clave K):
  rv = get_hmac_sha256(cont, cont_len, &hmac, &hmac_len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: generating HMAC failed: %d\n", rv);
    goto out;
  }

  // 2) Pasar el HMAC a Base64:
  rv = get_hmac_b64(hmac, hmac_len, &hmac_b64, &hmac_b64len);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: parsing HMAC to Base 64: %d\n", rv);
    goto out_free_hmac;
  }

  // 3) Escribir contenido y HMAC en el fichero fd -> cont + sep + HMAC(base
  // 64):
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
// 3. Fichero está VACÍO (size == 0) => Solo fichero fd vacío
static int val_metadata(struct file *f) {
  struct inode *inode = file_inode(f);
  int rv, fsize = 0;

  if (!(f->f_mode & FMODE_WRITE) || !(f->f_flags & O_APPEND)) {
    printk(KERN_ERR "Error printH: fd given must be writable (O_WRONLY/O_RDWR)\n");
    return -EBADF;
  }

  rv = file_permission(f, MAY_WRITE | MAY_APPEND);
  if (rv < 0) {
    printk(KERN_ERR "Error printH: permissions VFS/LSM denied: %d\n", rv);
    return rv;
  }

  fsize = i_size_read(inode);
  if (fsize != 0) {
    printk(KERN_ERR
           "Error printH: fd given must refer to an empty file (size=%d)\n",
           fsize);
    return -ENOTEMPTY;
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
  printk(KERN_DEBUG "mywrite: printH OK (content certificated by "
                    "HMAC(SHA-256)) for fd %d (%d bytes written)\n",
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
