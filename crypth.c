#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kstrtox.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/base64.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include "K_embedded.h"   // unsigned char K[]; unsigned int K_len=64;

enum { BUFSIZE = 100 };

MODULE_LICENSE ("Dual BSD/GPL");
MODULE_AUTHOR ("Noel");

// fd global para comunicar mywrite y myread -> proteger de concurrencia -> último fd usado:
int fd_glob = -1;

// Lock para proteger acceso a fd_glob -> IRQ(Interrupt Request -> Interrupción de hardware/CPU):
static DEFINE_SPINLOCK(lock_fd);

// Puntero de referencia/entrada al fichero que crearemos en /proc --> /proc/fddev
static struct proc_dir_entry *ent;

// Separador textual entre el contenido y el HMAC en base 64:
static const char sep[] = "\n-HMAC(SHA-256)-\n";
static const char sep_len = sizeof(sep) - 1; // NO contar '\0'


// Helper --> Escribir todo el contenido que se pase en f:
// Devuelve bytes escritos (off) en éxito <-> <0 en error <-> 0 si encuentra EOF
static ssize_t 
write_full(struct file *f, const char *buf, size_t len, loff_t *pos)
{
    ssize_t off = 0;
    while (off < len) {
        ssize_t w = kernel_write(f, buf + off, len - off, pos);
        if (w < 0)  
          return w;
        if (w == 0) 
          return -EIO;
        off += w;
    }
    return off;
}

// Escribir en fichero f (de fd) -> cont + sep + HMAC
// Devuelve >0 = bytes escritos totales <-> <0 = error
static ssize_t
write_cont_hmac(struct file *f, const char *cont, size_t cont_len, const char *hmac_b64, size_t hmac_b64len)
{
  loff_t pos = 0;
  ssize_t w, total = 0;

  w = write_full(f, cont, cont_len, &pos);
  if (w < 0) 
    return w;
  total += w;

  w = write_full(f, sep, sep_len, &pos);
  if (w < 0)
    return w;
  total += w;

  w = write_full(f, hmac_b64, hmac_b64len, &pos);
  if (w < 0)
    return w;
  total += w;

  return total;
}

// Calcular el HAMC(SHA-256) con la clave K del contenido que nos pasan:
// Devuelve 0 en éxito <-> <0 en error
static ssize_t
compute_hmac_sha256(const u8 *buf, size_t buf_len, u8 **hmac, unsigned int *hmac_len)
{
  ssize_t rc;
  // Handler del Crypto API del kernel para un hash síncrono --> shash => Transformador:
  struct crypto_shash *tfm;

  // 1) HAMC(SHA-256) como algoritmo => pide al Crypto API del kernel handler sincrónico (shash) para HMAC-SHA256
  tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
  if (IS_ERR(tfm))
      return PTR_ERR(tfm);

  // 2) Asocia la clave al “transform” (handler)
  rc = crypto_shash_setkey(tfm, K, K_len);
  if (rc)
      goto out_free_tfm;

  // 3) Reservar memoria para el HMAC (calculando su tamaño)
  *hmac_len = crypto_shash_digestsize(tfm);
  *hmac = kmalloc(*hmac_len, GFP_KERNEL);
  if (!*hmac) {
      rc = -ENOMEM;
      goto out_free_tfm;
  }

  // 4) Calcular el HMAC en una sola llamada (one-shot):
  // SHASH_DESC_ON_STACK(desc, tfm) --> macro (<crypto/hash.h>) crea en la pila un bloque de memoria del kernel => sizeof(struct shash_desc) + crypto_shash_descsize(tfm)
  // struct shash_desc *desc --> estado intermedio del HMAC mientras se procesa -> Le asociamos el algoritmo de HMAC(SHA-256) -> Handler/transformador
  SHASH_DESC_ON_STACK(desc, tfm);
  desc->tfm = tfm;

  // 5) flujo: init -> update -> final en un paso sobre buf (contenido) => Cálculo final del HMAC
  rc = crypto_shash_digest(desc, buf, buf_len, *hmac);
  
out_free_tfm:
    crypto_free_shash(tfm);
    return rc;
}

// Calcula HMAC(SHA-256) con la clave K embebida del contenido que le pasamos:
// Devuelve => 0 en éxito o <0 en error
static ssize_t 
get_hmac(const char *buf, size_t buf_len, u8 **hmac, int *hmac_len, char **hmac_b64, size_t *hmac_b64len)
{
  ssize_t rc;

  // 1) HMAC(SHA-256)(K, buf) --> calcular el HMAC del contenido leído del fichero -> f:
  rc = compute_hmac_sha256((const u8 *)buf, buf_len, hmac, hmac_len);
  if (rc)
    return rc;

  // 2) Calcular espacio de Base64(HMAC):
  size_t hmac_b64cap = BASE64_CHARS(*hmac_len);
  *hmac_b64 = kmalloc(hmac_b64cap, GFP_KERNEL);
  if (!*hmac_b64) { 
    kfree(*hmac);
    return -ENOMEM; 
  }

  // 3) Codificar el HMAC a Base64 y guardar la longitud real escrita en b64len
  *hmac_b64len = base64_encode(*hmac, *hmac_len, *hmac_b64);
  if (*hmac_b64len < 0) {
    kfree(*hmac);
    kfree(*hmac_b64);
    return *hmac_b64len; 
  }

  return 0;
}

// Función para certificar el contenido que queremos poneren el fichero dado por 'fd' con HMAC(SHA-256) con clave K
// Devuelve => >0 = bytes añadidos <=> <0 = error
static ssize_t
printH (int fd)
{
  ssize_t rc;
  const char cont[] = "This is an authentic content to be validated by HMAC(SHA-256)!!";
  const size_t cont_len = sizeof(cont) - 1; // NO contar '\0'
  u8 *hmac = NULL;
  int hmac_len = 0;
  char *hmac_b64 = NULL;
  size_t hmac_b64len = 0;

  if (fd < 0)
    {
      printk (KERN_ERR "printH: invalid fd (%d)\n", fd);
      return -EBADF;
    }
  
  // 1) Comprobar que el fd es válido en ESTE proceso y que es O_RDWR:
  struct file *f = fget(fd);
  if (!f) {
    printk(KERN_ERR "Error printH: fget failed for fd %d\n", fd);
    return -EBADF;
  }

  // 2) Comprobar que el fd permite ESCRIBIR (no hace falta leer)
  if (!(f->f_mode & FMODE_WRITE)) {
    printk(KERN_ERR "Error printH: fd %d must be writable (O_WRONLY/O_RDWR)\n", fd);
    rc = -EBADF;
    goto out_put;
  }

  // 3) Comprobar que el fichero está VACÍO (size == 0) => Solo fichero fd vacío apto
  struct inode *inode = file_inode(f);
  loff_t fsize = i_size_read(inode);
  if (fsize != 0) {
    printk(KERN_ERR "Error printH: fd %d must refer to an empty file (size=%lld)\n",
            fd, fsize);
    rc = -ENOTEMPTY;
    goto out_put;
  }

  // 4) Certificar (HMAC(SHA 256)) con clave K):
  rc = get_hmac(cont, cont_len, &hmac, &hmac_len, &hmac_b64, &hmac_b64len);
  if (rc < 0) {
    printk(KERN_ERR "Error printH: generating HMAC failed for fd %d: %zd\n", fd, rc);
    goto out_put;
  }

  // 5) Escribir contenido y HMAC en el fichero fd -> cont + sep + HMAC(base 64):
  rc = write_cont_hmac(f, cont, cont_len, hmac_b64, hmac_b64len );
  if (rc < 0) {
    printk(KERN_ERR "Error printH: writing content in fd %d: %zd\n", fd, rc);
    goto out_free_hmac;
  }
  printk(KERN_INFO "printH: file fd=%d has been written with content certificated by HMAC(SHA-256)\n", fd);

out_free_hmac:
  kfree(hmac_b64);
  kfree(hmac);
out_put:
  fput(f);
  return rc;
}

// Se ejecuta al escribir en /proc/fddev desde espacio de user
// Escribe contenido del kernel certificado en fd (userpace)
// Devuelve bytes escritos/pos en /proc/fddev (c) en éxito <-> <0 en error <-> 0 EOF
static ssize_t
mywrite (struct file *file, const char __user *ubuf, size_t count,
	 loff_t *ppos)
{
  int fd;
  int c;
  char buf[BUFSIZE];
  ssize_t written;
  unsigned long flags;

  // 1) Ver si es la primera vez que se llama a "write" para este fichero --> sino EOF => single-shot:
  if (*ppos > 0 || count > BUFSIZE) {
    printk (KERN_ERR "/proc/fddev: Only one write allowed or too much bytes sent (100 bytes max)\n");
    return -EFAULT;
  }
  printk (KERN_DEBUG "/proc/fddev: write handler\n");

  // 2) Copia "count" bytes desde memoria de espacio de user (ubuf) a memoria del kernel (buf)
  // y cambiar puntero de seguimiento del fichero /proc/fddev:
  if (copy_from_user (buf, ubuf, count)) {
    printk (KERN_ERR "/proc/fddev: write handler failed\n");
    return -EFAULT;
  }
  c = strlen (buf);
  printk (KERN_DEBUG "/proc/fddev write: written %d bytes from the user\n",
	  c);
  *ppos = c;

  // 3) Parsear descriptor de fichero que le pasa el user (fd) a int -> kstrtoint(char[], base, &res) -> y cambiar valor de fd_glob (protegido)
  if (kstrtoint (buf, 10, &fd))
    {
      printk (KERN_ERR "/proc/fddev: can not be parsed fd from userspace\n");
      return -EINVAL;
    }
  spin_lock_irqsave(&lock_fd, flags);
  fd_glob = fd;
  spin_unlock_irqrestore(&lock_fd, flags);

  // 4) Escribir contenido del kernel certificado en fd -> HMAC(SHA-256) con clave K embebida:
  written = printH(fd);
  if (written < 0) {
      printk(KERN_ERR "Error mywrite: printH failed for fd %d: %zd\n", fd, written);
      return written;
  }
  printk(KERN_DEBUG "mywrite: printH OK (content certificated by HMAC(SHA-256)) for fd %d (%zd bytes written)\n", fd, written);

  return c;
}

// Se ejecuta al leer en /proc/fddev desde espacio de user
// Pasarle el contenido guardado en /proc/fddev a userpace
// Devuelve > 0 (bytes leídos -> len) <-> = 0 (EOF) <-> < 0 (error)
static ssize_t
myread (struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
  char buf[BUFSIZE];
  int len = 0;
  unsigned long flags;
  int fd;

  // 1) Ver si es la primera vez que se llama a "read" para este fichero --> sino EOF => single-shot 
  if (*ppos > 0 || count < BUFSIZE) {
    printk (KERN_ERR "/proc/fddev: Only one read allowed or too much bytes requested (100 bytes max)\n");
    return 0;
  }
  printk (KERN_DEBUG "/proc/fddev: read handler\n");

  // 2) Escribe contenido solicitado por userspace -> sprintf(destino, formato, valores…) -> fd_glob (protegido) -> último fd/canal utilizado
  spin_lock_irqsave(&lock_fd, flags);
  fd = fd_glob;
  spin_unlock_irqrestore(&lock_fd, flags);
  len += sprintf (buf, "fd = %d\n", fd);

  // 3) Copia "len" bytes desde memoria del kernel (buf) a memoria de usuario (ubuf):
  if (copy_to_user (ubuf, buf, len)) {
    printk (KERN_ERR "/proc/fddev: write handler failed\n");
    return -EFAULT;
  }

  // 4) Puntero de seguimiento (*ppos) del fichero en el último byte copiado en memoria de userspace (len)
  *ppos = len;
  printk (KERN_DEBUG "/proc/fddev myread: read %d bytes by userspace\n",
	  len);
  return len;
}

// Asociar acciones/manejadores para /proc/fddev:
// Utilizar struct proc_ops (en lugar de struct file_operations) a partir del kernel 5.6
static const struct proc_ops myops = {
  .proc_read = myread,
  .proc_write = mywrite,
};

// Cargar LKM:
static int
simple_init (void)
{
  // 1) Imprime K en hexadecimal en los logs del kernel (/var/log/kern.log) -> %*phC separa bytes con ':' => SOLO EN PRUEBAS
  printk (KERN_DEBUG "K (64Bytes) loaded = %*phC\n", K_len,
	  K);

  // 2) Crear fichero en /proc -> /proc/fddev:
  ent = proc_create ("fddev", 0660, NULL, &myops);
  if (!ent) {
    printk (KERN_ERR "Error creating file in /proc");
    return -ENOMEM;
  }
  printk (KERN_INFO "New proc file created: /proc/fddev\n");

  return 0;
}

// Descargar LKM:
static void
simple_cleanup (void)
{
  // 1) Borrar referencia al fichero creado en /proc -> /proc/fddev:
  proc_remove (ent);
  printk (KERN_INFO "Proc file deleted: /proc/fddev\n");
}

module_init (simple_init);
module_exit (simple_cleanup);
