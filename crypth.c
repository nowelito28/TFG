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

// Clave K embebida de 32 bytes (generada con xxd -i) --> Creado key_embedded.h desde un binario (key.bin)
#include "K_embedded.h"   // define: unsigned char K[]; unsigned int K_len=32;

#define BUFSIZE  100		// Constante global
#define KEY_SIZE 32		  // Longitud en bytes que queremos que tome la clave => K

// Metadatos del modulo:
MODULE_LICENSE ("Dual BSD/GPL");
MODULE_AUTHOR ("Noel");

// Parámetros del módulo --> Valor por defecto si no se le pasa al cargar el modulo:

// fd --> descriptor de fichero (fd) que se va a pasar entre procesos (desde espacio de user)
// fd => inicialiar fd = -1 (valor inválido) --> hasta que no sea váido --> NO buscar en él
static int fd = -1;
module_param (fd, int, 0660);

// Puntero de referencia/entrada al fichero que crearemos en /proc --> /proc/fddev
static struct proc_dir_entry *ent;

// Puntero de seguimiento/salida para strtol --> lo sobreescribe
char *endptr = NULL;

// Leer chunk de 1024 bytes máx del fichero fd (para no usar demasiada memoria del kernel)
const size_t chunk = 1024;

// Separador textual entre el mensaje y el HMAC codificado (7 chars + '\0')
static const char *sep = "\n\n---\n\n";
static const size_t seplen = strlen(sep); // 7 bytes


// Calcula HMAC(SHA-256) con la clave K embebida del contenido del fichero f y lo concatena al fichero f en buf_len:
// buf + "\n\n---\n\n" + base64(HMAC) => Devuelve bytes añadidos o <0 en error
static ssize_t 
get_hmac(struct file *f, const char *buf, size_t buf_len)
{
  int rc;               // Registro de errores
  u8 *hmac = NULL;    // Buffer de salida del HMAC (array de bytes/chars)
  unsigned int hmac_len = 0;  // Longitud del HMAC (se sobreescribe las variables)
  char *b64 = NULL;   // HMAC en Base64
  ssize_t ret = 0;    // Bytes añadidos o <0 en error

  // 1) HMAC(SHA-256)(K, buf) --> calcular el HMAC del contenido leído del fichero -> f:
  rc = compute_hmac_sha256((const u8 *)K, KEY_SIZE, (const u8 *)buf, (size_t)buf_len, &hmac, &hmac_len);
  if (rc)   // Ver si ha habido error
    return rc;

  // 2) Calcular Base64(HMAC):
  // Espacio necesario para el Base64 del HMAC
  size_t b64cap = BASE64_CHARS(hmac_len) + 1; // +1 para '\0'
  b64 = kmalloc(b64cap, GFP_KERNEL);  // Reservar memoria para el Base64 del HMAC -> GFP_KERNEL porque puede dormir
  if (!b64) { 
    ret = -ENOMEM; 
    goto out_free_hmac; 
  }

  // Codificar el HMAC a Base64 y guardar la longitud real escrita en b64len
  int b64len = base64_encode(hmac, hmac_len, b64);
  if (b64len < 0) { // Error al code base 64
    ret = b64len; 
    goto out_free_b64; 
  }
  b64[b64len] = '\0';

  // 3) Concatenar al final del contenido leído (buf_len)
  // Posición de escritura al final del contenido leído
  loff_t pos_write = (loff_t)buf_len;

  // Escribir el separador al final del fichero f: --> Asegurarnos que se escribe todo con un bucle
  size_t off = 0;
  while (off < seplen) {
    ssize_t w = kernel_write(f, sep + off, seplen - off, &pos_write);
    if (w <= 0) { 
      ret = w; 
      goto out_free_b64; 
    }
    off += (size_t)w;
  }

  // Escribir el Base64 del HMAC al final del fichero f después del separador:
  off = 0;
  while (off < (size_t)b64len) {
    w = kernel_write(f, b64 + off, (size_t)b64len - off, &pos_write);
    if (w <= 0) {
      ret = w; 
      goto out_free_b64;
    }
    off += (size_t)w;
  }

  // Success --> devolver bytes añadidos al contenido original (buf_len)
  ret = (ssize_t)(seplen + b64len);

// Liberar memoria reservada y salir --> 0 = ya estaba certificado (todavía NO) <=> >0 = bytes añadidos <=> <0 = error
out_free_b64:
  kfree(b64);
out_free_hmac:
  kfree(hmac);
  return ret;
}

// Leer el contenido del fichero 'f' hasta EOF o hasta encontrar el separador del HMAC (si ya está certificado)
// Devuelve en *buf un buffer (kvmalloc) con el contenido leído y en *buf_len su longitud
// Si encuentra separador => *already=0 y el contenido devuelto llega hasta justo antes del separador
// Retorna 0 en éxito <=> <0 si error
static int
read_file (struct file *f, char **buf, size_t *buf_len)
{
  int rc = 0;        // Registro de errores
  loff_t size = i_size_read(file_inode(f)); // Tamaño del fichero f (bytes)
  loff_t pos = 0;           // Posición actual de lectura en el fichero f --> inicialmente 0
  loff_t pos_prev = 0;      // Posición anterior de lectura (para buscar separador)
  int sep_len = strlen(sep); // Longitud del separador (7 bytes)

  // Aceptar ficheros vacíos --> Enviar buffer vacío y longitud 0
  if (size <= 0) {
    *buf = NULL;
    *buf_len = 0;
    return 0;
  }

  // Reserva un buffer del tamaño actual del fichero en memoria del kernel
  *buf = kvmalloc(size, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  // Leer el fichero 'f' --> (1024 bytes máx = chunk) ó hasta EOF (pos = size) o hasta encontrar el separador
  while (pos < size) {
    // Leer un 'chunk' de 1024 bytes ó lo que quede hasta EOF si es menor
    size_t to_read = (size - pos > (loff_t)chunk) ? chunk : (size_t)(size - pos);
    // kernel_read actualiza posr --> posición después de leer
    loff_t posr = pos;
    // Leer desde el fichero 'f' en memoria del kernel (buf + pos --> posición por la que se encuentra el buffer del kernel) 
    // hasta to_read bytes --> EOF o tope de chunk
    ssize_t r = kernel_read(f, buf + pos, to_read, &posr);
    if (r < 0) {  // Error en la lectura --> Saltar a etiqueta de limpieza de memoria y salir con el código de error
       rc = r;
       goto err;
    }
    if (r == 0) // EOF inesperado al saber ya el tamaño del fichero de antemano
      break;
    // Actualizar puntero de lectura hasta donde se ha quedado kernel_read
    pos = posr;
  }

  // Cambiar el tamaño del buffer al tamaño real leído (pos)
  *buf_len = (size_t)pos;
  return 0;   

  // Liberar memoria en caso de error y salir con él:
err:
  kvfree(*buf);
  *buf = NULL;
  *buf_len = 0;
  return rc;
}


// Creamos nueva función para certificar el contenido que tenga el fichero dado por 'fd' con HMAC(SHA-256) con clave K
static ssize_t
printH (int fd)
{
  char *buf = NULL;   // Buffer en memoria del kernel --> contenido leído a certificar
  size_t buf_len = 0; // Longitud del buffer --> contenido leído
  int rc;			        // Registro de errores

  // Ver que tenemos un fd válido en ESTE proceso o no se ha pasado ningún fd de momento::
  if (fd < 0)
    {
      printk (KERN_ERR "printH: invalid fd (%d)\n", fd);
      return -EBADF;		// fd inválido en ESTE proceso --> errno = bad file descriptor
    }
  
  // 1) Comprobar que el fd es válido en ESTE proceso y que es O_RDWR:
  struct file *f = fget(fd);
  if (!f) {
    printk(KERN_ERR "Error printH: fget failed for fd %d\n", fd);
    return -EBADF;
  }
  // Comprobar que el fd permite leer y escribir
  if (!(f->f_mode & FMODE_READ) || !(f->f_mode & FMODE_WRITE)) {
    printk(KERN_ERR "Error printH: fd %d must be O_RDWR\n", fd);
    rc = -EBADF;
    goto out_put;
  }

  // 2) Leer hasta EOF o hasta separador:
  rc = read_file(f, &buf, &buf_len, &already);
  if (rc < 0) 
    goto out_put;

  // 3) Certificar (HMAC(SHA 256) con clave K) y poner al final:
  rc = get_hamc(f, buf, buf_len);
  if (rc < 0) {
    printk(KERN_ERR "Error printH: generating HMAC failed para fd %d: %zd\n", fd, rc);
    goto out_free;
  }
  printk(KERN_INFO "printH: file fd=%d certificated with HMAC(SHA-256) and appended at the bottom\n", fd);

  // Liberar memoria reservada y salir --> 0 = ya estaba certificado (TODAVÍA NO -> ASUMIR SOLO NO CERTIFICADOS) <=> >0 = bytes añadidos <=> <0 = error
  // Etiqueta para saltar al flujo de limpieza y salida con antelación si es necesario:
out_free:
  kvfree(buf);
out_put:
  fput(f);
  return rc;
}

// Se ejecuta al escribir en /proc/fddev desde espacio de user
static ssize_t
mywrite (struct file *file, const char __user *ubuf, size_t count,
	 loff_t *ppos)
{
  // Variables temporales:
  // c --> última posición de escritura (char) en el fichero "/proc/fddev"
  // fd_aux --> variable (fd -> descriptor de fichero) que se escribe desde el user
  int c, fd_aux;
  char buf[BUFSIZE];		// Array de chars con el tamaño del buffer (100) -> buffer/memoria temporal en stack del kernel (copiar lo que envía el espacio de user)
  ssize_t added;           // bytes añadidos por printH (sep + b64) o <0 en error

  // Ver si es la primera vez que se llama a "write" para este fichero --> sino EOF => semántica single-shot
  // *ppos > 0 --> puntero de posición es mayor que 0 = se ha escrito algo ya dentro del fichero /proc/fddev
  // count >= BUFSIZE --> tamaño que el user pide escribir (count) tiene que ser menor que el buffer definido (100 bytes) --> >= para incluir el '\0' al final
  if (*ppos > 0 || count >= BUFSIZE)
    return -EFAULT;		// Si se cumple una de las dos --> devolver -EFAULT (dirección user inválida)

  // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se lea en "fddev" --> Loggea
  printk (KERN_DEBUG "write handler\n");

  // // Copia "count" bytes desde memoria de espacio de user (ubuf) a memoria del kernel (buf)
  if (copy_from_user (buf, ubuf, count))
    // Devuelve 0 si ha salido bien --> sino => devuelve nº de bytes que no se han podido copiar
    return -EFAULT;		// en userland => errno = EFAULT, “Bad address”

  // Parsear descriptor de fichero que le pasa el user (fd) en forma de string
  // kstrtoint(str, base, &res) --> convierte string a int => devulve 0 en éxito => res contiene el valor convertido => str/buf en memoria del kernel
  // kstrtoint_from_user(ubuf, count, base, &res) --> convierte string a int desde memoria de user (igual pero desde ubuf)
  if (kstrtoint (buf, 10, &fd_aux))
    {
      // No se pudo convertir nada
      return -EINVAL;		// errno = invalid argument
    }

  // Asignamos la variable que hemos extraído --> fd (descriptor de fichero) de referencia para hacer el certificado con HMAC:
  fd = fd_aux;

  // Certificar contenido del fichero fd dado por el user con HMAC(SHA-256) con clave K:
  added = printH(fd);
  if (added < 0) {
      printk(KERN_ERR "Error mywrite: printH fallo para fd %d: %zd\n", fd, added);
      return added;
  }

  // c = longitud del string "buf" copiado de "ubuf" sin contar '\0'
  c = strlen (buf);
  printk (KERN_DEBUG "write to /proc/fddev: written %d bytes from the user\n",
	  c);

  printk(KERN_INFO "mywrite: printH OK (content certificated by HMAC(SHA-256)) for fd %d (appended %zd bytes)\n", fd, added);

  // Cambiar el puntero de seguimiento/entrada de escritura del fichero "/proc/mydev" al último char copiado
  // Y devolver la posición por donde se encuentra el fichero = nº de bytes hemos recibido del user
  *ppos = c
  return c;
}

// Se ejecuta al leer en /proc/fddev desde espacio de user
static ssize_t
myread (struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
  // Variables locales:
  char buf[BUFSIZE];		// Array de chars con el tamaño del buffer (100) -> buffer/memoria temporal en stack del kernel (respuesta para espacio de user)
  int len = 0;			// Numero bytes escritos en buf

  // Ver si es la primera vez que se llama a "read" para este fichero --> sino EOF => semántica single-shot 
  // *ppos > 0 --> puntero de posición es mayor que 0 = se ha leído algo ya dentro del fichero /proc/fddev
  // count < BUFSIZE --> tamaño que el user pide leer (count) menor que el buffer definido (100 bytes)
  if (*ppos > 0 || count < BUFSIZE)
    return 0;			// Si se cumple una de las dos --> devolver EOF (0)

  // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se lea en "fddev" --> Loggea
  printk (KERN_DEBUG "read handler\n");

  // sprintf(destino, formato, valores…) escribe una cadena de texto en un buffer de memoria (destino)
  // Devuelve el número de caracteres escritos (sin contar el \0 final) --> len
  // Escribimos en el buffer creado al inicio de la función estas dos frases con los parametros (una después de la otra)
  len += sprintf (buf, "fd = %d\n", fd);

  // Copia "len" bytes desde memoria del kernel (buf) a memoria de usuario (ubuf)
  if (copy_to_user (ubuf, buf, len))
    // Devuelve 0 si ha salido bien --> sino => devuelve nº de bytes que no se han podido copiar
    return -EFAULT;		// en userland => errno = EFAULT, “Bad address”

  // Ponemos finalmente el puntero de seguimiento (*ppos) del fichero en el último byte copiado en memoria de user (len)
  // Y retornamos dicha posición del último byte (len)
  *ppos = len;
  printk (KERN_DEBUG "read from /proc/fddev: read %d bytes to the user\n",
	  len);
  return len;			// > 0 (se han leído bytes) | = 0 (EOF) | < 0 (error)
}

// Tabla de operaciones del fichero creado "fddev"
// Asociar acciones/manejadores que se pueden hacer en este fichero
// Utilizar struct proc_ops (en lugar de struct file_operations) a partir del kernel 5.6
static const struct proc_ops myops = {
  .proc_read = myread,
  .proc_write = mywrite,
};

// Cargar LKM:
// Inicializar ent con la creacion del fichero "mydev" en /proc
// con todos los permisos (rw) para el root y el grupo
static int
simple_init (void)
{
  // La clave K de 32 bytes ya viene embebida desde key_embedded.h --> comprobar que es de 32 bytes en tiempo de compilación
  BUILD_BUG_ON(sizeof(K) != KEY_SIZE);

  // Imprime K en hexadecimal en los logs del kernel (/var/log/kern.log)
  // %*phN muestra el buffer en hex sin espacios
  // %*phC muestra bytes (del buffer) separados por ':'
  printk (KERN_DEBUG "K (32Bytes) generated in the load = %*phC\n", KEY_SIZE,
	  K);

  // Codificar K en Base64 para imprimirlo en los logs del kernel
  // Fórmula: base64_len = 4 * ((input_len + 2) / 3)
  // base64_encode(const u8 *src, size_t srclen, char *dst) --> devuelve nº bytes escritos en dst (o error <0)
  int b64len = base64_encode ((const u8 *) K, KEY_SIZE, Kb64);
  if (b64len < 0)
    {
      printk (KERN_ERR "base64_encode(K) failed: %d\n", b64len);
    }
  else
    {
      Kb64[b64len] = '\0';
      printk (KERN_DEBUG "K (Base64) = %s\n", Kb64);
    }

  // Crear el primer fichero en /proc para la funcionalidad básica de
  // escribir el fd del fichero donde quiere escribir el contenido certificado
  printk (KERN_INFO "Creating new proc file: /proc/fddev\n");
  ent = proc_create ("fddev", 0660, NULL, &myops);
  // Comprobar errores -> si falla => ent==NULL => deberia devolver -ENOMEM 
  if (!ent)
    {
      return -ENOMEM;
    }

  return 0;
}

// Descargar LKM:
// Borrar referencia/entrada a los ficheros creados en /proc
static void
simple_cleanup (void)
{
  printk (KERN_INFO "Delating proc file: /proc/fddev\n");
  proc_remove (ent);
}

module_init (simple_init);
module_exit (simple_cleanup);
