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
#include <linux/random.h>
#include <linux/base64.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/err.h>

#define BUFSIZE  100		// Constante global
#define KEY_SIZE 32		// Longitud en bytes que queremos que tome la clave => K

// Metadatos del modulo:
MODULE_LICENSE ("Dual BSD/GPL");
MODULE_AUTHOR ("Noel");

// Parámetros del módulo --> Valor por defecto si no se le pasa al cargar el modulo:

// fd --> descriptor de fichero (fd) que se va a pasar entre procesos (desde espacio de user)
// fd => inicialiar fd = -1 (valor inválido) --> hasta que no sea váido --> NO buscar en él
static int fd = -1;
module_param (fd, int, 0660);

// Clave simétrica en memoria del kernel (K) --> 32 bytes aleatorios
static char K[KEY_SIZE];
// Clave K en Base64: cada 3 bytes se codifican en 4 caracteres -> si no es múltiplo de 3 se añade padding '=' al final
char Kb64[BASE64_CHARS (KEY_SIZE) + 1];	// +1 para '\0'

// Puntero de referencia/entrada al fichero que crearemos en /proc --> /proc/fddev
static struct proc_dir_entry *ent;
// Puntero de referencia/entrada al segundo fichero que crearemos en /proc --> /proc/hmacdev
static struct proc_dir_entry *ent_hmac;

// Puntero de seguimiento/salida para strtol --> lo sobreescribe
char *endptr = NULL;



// Crea el HMAC-SHA256 del mensaje 'msg' con la clave 'key' de longitud 'keylen'
// Calcula -> 'out_hmac' el HMAC (array de bytes) y en 'out_hlen' su longitud
// Devuelve 0 si todo va bien --> error: un código negativo estilo errno (-EINVAL, -ENOMEM)
static int
compute_hmac_sha256 (const u8 *key, size_t keylen,
		     const u8 *msg, size_t msglen,
		     u8 **out_hmac, unsigned int *out_hlen)
{
  // Comprobar no hay punteros nulos:
  if (!key || !msg || !out_hmac || !out_hlen)
    {
      return -EINVAL;
    }

  // tfm -> transform del API de crypto del kernel (tipo síncrono (shash))
  struct crypto_shash *tfm;
  // desc -> descriptor que contiene tfm y contexto interno del algoritmo
  struct shash_desc *desc;
  // digest -> array de bytes donde se guarda el HMAC resultante
  u8 *digest;
  // rc -> acumulador de códigos de retorno
  int rc;
  // dlen -> tamaño del digest del algoritmo (32 para SHA-256)
  unsigned int dlen;

  // 1) Crear tfm para HMAC-SHA256:
  // Pide al subsistema crypto una implementación de hmac(sha256)
  tfm = crypto_alloc_shash ("hmac(sha256)", 0, 0);
  if (IS_ERR (tfm))
    {
      return PTR_ERR (tfm);
    }

  // 2) Cargar la clave secreta K en el transform tfm del HMAC:
  rc = crypto_shash_setkey (tfm, key, keylen);
  if (rc)
    {
      goto out_free_tfm;	// Saltar a la etiqueta(flujo) out_free_tfm
    }

  // 3) Consultar tamaño del resultado del HMAC (digest) y reservar memoria para la salida/resultado (digest)
  dlen = crypto_shash_digestsize (tfm);
  // Reserva el buffer de salida (memoria en kernel) con GFP_KERNEL -> puede dormir
  digest = kmalloc (dlen, GFP_KERNEL);
  if (!digest)
    {
      rc = -ENOMEM;
      goto out_free_tfm;
    }

  // 4) Crear descriptor del hash (shash_desc -> desc) y reservar memoria para él
  // crypto_shash_descsize(tfm) te dice cuántos bytes extra necesitas para el contexto interno del algoritmo
  desc = kmalloc (sizeof (*desc) + crypto_shash_descsize (tfm), GFP_KERNEL);
  if (!desc)
    {
      kfree (digest);
      rc = -ENOMEM;
      goto out_free_tfm;
    }
  // Asociar el tfm al descriptor:
  desc->tfm = tfm;

  // 5) Calcular HMAC-SHA256 del mensaje 'msg' con la clave 'key' -> Flujo clásico shash:
  // - init prepara el estado interno del algoritmo:
  rc = crypto_shash_init (desc);
  if (!rc)
    {
      // - update procesa los datos del mensaje:
      rc = crypto_shash_update (desc, msg, msglen);
    }
  if (!rc)
    {
      // - final termina y escribe el HMAC en digest:
      rc = crypto_shash_final (desc, digest);
    }
  // Detectar si ocurre algún error en el proceso:
  if (rc)
    {
      kfree (desc);
      kfree (digest);
      goto out_free_tfm;
    }

  // 6) Success --> devolver resultado al caller --> caller hace kfree() de digest al llamarlo:
  *out_hmac = digest;
  *out_hlen = dlen;
  // Liberar memoria del kernel que ya no se usa (desc y tfm):
  kfree (desc);
  crypto_free_shash (tfm);
  return 0;			// Salir en éxito

  // Etiquta para liberar memoria de tfm en caso de ERROR y devolver dicho error:
out_free_tfm:
  crypto_free_shash (tfm);
  return rc;
}

// Concatena el mensaje 'msg' (de longitud 'msglen') con el separador y el HMAC en Base64
// [msg (binario)] + "\n\n---\n\n" + [HMAC en Base64] + "\n"
static int
concat_with_hmac_b64 (const char *msg, size_t msglen,
		      const u8 *hmac, size_t hlen, char **out, size_t *outlen)
{
  // Comprobar no hay punteros nulos:
  if (!msg || !hmac || !out || !outlen)
    return -EINVAL;

  // Separador textual entre el mensaje y el HMAC codificado (7 chars + '\0')
  static const char *sep = "\n\n---\n\n";
  size_t seplen = strlen (sep);	// 7 bytes
  // Bytes necesarios para codificar el HMAC en Base64
  size_t b64cap = BASE64_CHARS (hlen) + 1;	// +1 para '\0' para ser string
  // Buffer temporal de la cadena Base64 del HMAC:
  char *b64 = NULL;
  // Buffer final de salida (msg + sep + b64):
  char *buf = NULL;
  // Longitud real escrita por base64_encode (sin contar '\0'):
  int b64len;
  // Registro de errores:
  int rc = 0;

  // Reservar memoria para el Base64 del HMAC:
  b64 = kmalloc (b64cap, GFP_KERNEL);
  if (!b64)
    {
      return -ENOMEM;
    }

  // Codificar el HMAC a Base64 y guardar la longitud real escrita en b64len
  b64len = base64_encode (hmac, hlen, b64);
  if (b64len < 0)
    {
      rc = b64len;
      goto out_free_b64;
    }
  b64[b64len] = '\0';		// Para ser string

  // Calcular longitud total de la salida (HMAC en Base64) y reservar memoria para ella
  *outlen = msglen + seplen + (size_t) b64len;
  buf = kmalloc (*outlen, GFP_KERNEL);
  if (!buf)
    {
      rc = -ENOMEM;
      goto out_free_b64;
    }

  // Construir salida sin usar funciones de string sobre 'msg'
  // Usar memcpy (y no strcat/strcpy) porque msg puede contener bytes nulos '/0'
  memcpy (buf, msg, msglen);
  memcpy (buf + msglen, sep, seplen);
  memcpy (buf + msglen + seplen, b64, b64len);

  // Success --> Devolver resultado al caller -> Caller hace el kfree() de buf (*out) al llamarlo
  *out = buf;
  rc = 0;

  // Etiquta para liberar memoria de b64 en caso de ERROR y devolver dicho error:
out_free_b64:
  kfree (b64);
  return rc;
}

// Creamos nueva función para cargar relacionado al fichero /proc/hamcdev => printH()
//--> Para escribir contenido (ubuf --> Payload) en un fichero dado, firmado con un HMAC(SHA-256) con clave K
static ssize_t
printH (struct file *file, const char __user *ubuf, size_t count,
	loff_t *ppos)
{
  // Buffer para guardar datos en memoria del kernel
  char buf[BUFSIZE];		// Buffer en memoria del kernel (100 bytes) --> Solo se pueden escribir 100 bytes de contenido a cetificar
  size_t msg_len = count;	// Longitud del mensaje que nos pasa el user (count)
  int rc;			// Registro de errores
  u8 *hmac = NULL;		// Buffer de salida del HMAC (array de bytes)
  unsigned int hlen = 0;	// Longitud del HMAC (se sobreescribe las variables)
  char *out = NULL;		// Buffer de salida final (mensaje + separador + HMAC en Base64)
  size_t outlen = 0;		// Longitud del buffer de salida final (se sobreescribe)

  // Ver que tenemos un fd válido en ESTE proceso o no se ha pasado ningún fd de momento::
  if (fd < 0)
    {
      printk (KERN_ERR "printH: invalid fd (%d)\n", fd);
      return -EBADF;		// fd inválido en ESTE proceso --> errno = bad file descriptor
    }

  // Semántica single-shot y control de tamaño
  if (*ppos > 0 || count >= BUFSIZE)
    {
      return -EFAULT;
    }

  // 1) Copiar Payload (contenido a certificar) -> buf desde espacio de user a memoria del kernel
  if (copy_from_user (buf, ubuf, msg_len))
    {
      return -EFAULT;		// en userland => errno = EFAULT, “Bad address”
    }

  // 2) HMAC-SHA256 sobre 'msg' con clave K --> obtener 'hmac' y 'hlen'
  rc =
    compute_hmac_sha256 ((const u8 *) K, KEY_SIZE, (const u8 *) buf, msg_len,
			 &hmac, &hlen);
  // Manejo de error:
  if (rc)
    {
      printk (KERN_ERR "printH: compute_hmac_sha256 failed: %d\n", rc);
      return rc;
    }

  // 3) Concatenar mensaje + separador + HMAC(Base64)
  rc = concat_with_hmac_b64 (buf, msg_len, hmac, hlen, &out, &outlen);
  if (rc)
    {
      printk (KERN_ERR "printH: concat_with_hmac_b64 failed: %d\n", rc);
      kfree (hmac);
      return rc;
    }

  // 4) Escribir 'out' (mensaje + separador + HMAC en Base64) en el fichero dado por 'fd'
  ssize_t written;		// Nº bytes escritos en 'f' (o error <0 en kernel_write)
  loff_t pos, *ppos_f;		// Posición de escritura (si aplica)
  size_t off = 0;		// Offset de bytes escritos (para asegurar escritura completa)

  struct file *f = fget (fd);	// Convertir fd a struct file *
  if (!f)
    {
      printk (KERN_ERR "Error printH: fget failed for fd %d\n", fd);
      kfree (out);
      kfree (hmac);
      return -EBADF;
    }

  // f->f_mode decide cómo gestionar la posición:
  //  - regular/posicional file --> si bits de f_mode NO son iguales (f->f_mode & FMODE_STREAM = 1)
  //  - stream (socket, pipe, etc.) --> si bits de f_mode son iguales (f->f_mode & FMODE_STREAM = 0)
  if (!(f->f_mode & FMODE_STREAM))
    {				// si es fichero posicional/regular(NO es stream) --> Multiplicaión de bit 
      // Ambas variables hacerlas iguales --> que apunten a la misma dirección de memoria
      pos = f->f_pos;		// guardar posición actual en pos (memoria del kernel)
      ppos_f = &pos;		// ppos_f apunta a la dirección de memoria de la copia (pos) para usar en kernel_write (en memoria del kernel)
    }
  else
    {
      ppos_f = NULL;
    }

  // Asegurar escritura completa (bucle) con control del offset
  while (off < outlen)
    {
      written = kernel_write (f, out + off, outlen - off, ppos_f);
      if (written < 0)
	{
	  fput (f);
	  kfree (out);
	  kfree (hmac);
	  printk (KERN_ERR "Error printH: kernel_write failed: %zd\n",
		  written);
	  return written;
	}
      off += (size_t) written;
    }

  // Modificar posición actual en f->f_pos si aplica (regular/posicional file)
  if (ppos_f)
    f->f_pos = pos;

  // Liberar struct file *"f" (decrementar contador de referencias y suelta cualquier estado asociado a la posición)
  fput (f);

  // Limpieza de variables reservadas en memoria del kernel:
  kfree (out);
  kfree (hmac);

  // Bytes escritos por el user:
  *ppos = msg_len;
  printk (KERN_DEBUG
	  "Successed printH: wrote %zu bytes (msg + sep + HMACb64)\n",
	  outlen);
  return msg_len;		// Devolver al user los bytes que nos ha pasado (msg_len)
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

  // Asignamos la variable que hemos extraído:
  fd = fd_aux;

  // c = longitud del string "buf" copiado de "ubuf" sin contar '\0'
  c = strlen (buf);
  printk (KERN_DEBUG "write to /proc/fddev: written %d bytes from the user\n",
	  c);

  // Cambiar el puntero de seguimiento/entrada de escritura del fichero "/proc/mydev" al último char copiado
  // Y devolver la posición por donde se encuentra el fichero = nº de bytes hemos recibido del user
  *ppos = c;
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

// Tabla de operaciones del fichero creado "hmacdev" para HMAC
// Asociar acciones/manejadores que se pueden hacer en este fichero
static const struct proc_ops myops_hmac = {
  .proc_write = printH,		// Escritura (write) en fichero 'fd' del payload firmado con HMAC
};

// Cargar LKM:
// Inicializar ent con la creacion del fichero "mydev" en /proc
// con todos los permisos (rw) para el root y el grupo
static int
simple_init (void)
{
  // Generar clave K de 32 bytes aleatorios
  //Espera a que el generador criptográfico del kernel (CRNG) esté inicializado
  //Puede dormir --> es correcto en module_init --> Devuelve 0 si OK
  int ret = wait_for_random_bytes ();
  if (ret)
    {
      printk (KERN_ERR "Error random: CRNG not ready (ret=%d)\n", ret);
      return ret;
    }
  // Rellenar K con 32 bytes criptográficamente aleatorios
  get_random_bytes (K, KEY_SIZE);
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

  // Crear el segundo fichero en /proc para la funcionalidad de escribir en el fd que el user escriba en /proc/fddev
  // el contenido que se le pase certificado con HMAC
  printk (KERN_INFO "Creating new proc file: /proc/hmacdev\n");
  ent_hmac = proc_create ("hmacdev", 0660, NULL, &myops_hmac);
  if (!ent_hmac)
    {
      proc_remove (ent);
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
  printk (KERN_INFO "Delating proc file: /proc/hmacdev\n");
  proc_remove (ent_hmac);
}

module_init (simple_init);
module_exit (simple_cleanup);
