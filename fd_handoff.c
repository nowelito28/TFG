#include <linux/module.h>
#include <linux/moduleparam.h>	// Cabeceras del kernel
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kstrtox.h>

#define BUFSIZE  100		// Constante global

// Metadatos del modulo:
MODULE_LICENSE ("Dual BSD/GPL");
MODULE_AUTHOR ("Noel");

// Parametro del modulo --> Valor por defecto si no se le pasa al cargar el modulo:
// fd --> descriptor de fichero (fd) que se va a pasar entre procesos (desde espacio de user)
// fd => inicialiar fd = -1 (valor inválido) --> hasta que no sea váido --> NO buscar en él
static int fd = -1;
module_param (fd, int, 0660);

// Puntero de referencia/entrada al fichero que crearemos en /proc
static struct proc_dir_entry *ent;

// Puntero de seguimiento/salida para strtol --> lo sobreescribe
char *endptr = NULL;

// Se ejecuta al escribir en /proc/mydev desde espacio de user
static ssize_t
mywrite (struct file *file, const char __user *ubuf, size_t count,
	 loff_t *ppos)
{
  // Variables temporales:
  // c --> última posición de escritura (char) en el fichero "/proc/mydev"
  // fd_aux --> variable (fd -> descriptor de fichero) que se escribe desde el user
  int c, fd_aux;
  char buf[BUFSIZE];		// Array de chars con el tamaño del buffer (100) -> buffer/memoria temporal en stack del kernel (copiar lo que envía el espacio de user)

  // Ver si es la primera vez que se llama a "write" para este fichero --> sino EOF => semántica single-shot
  // *ppos > 0 --> puntero de posición es mayor que 0 = se ha escrito algo ya dentro del fichero /proc/mydev
  // count >= BUFSIZE --> tamaño que el user pide escribir (count) tiene que ser menor que el buffer definido (100 bytes) --> >= para incluir el '\0' al final
  if (*ppos > 0 || count >= BUFSIZE)
    return -EFAULT;		// Si se cumple una de las dos --> devolver -EFAULT (dirección user inválida)

  // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se lea en "mydev" --> Loggea
  printk (KERN_DEBUG "write handler\n");

  // // Copia "count" bytes desde memoria de espacio de user (ubuf) a memoria del kernel (buf)
  if (copy_from_user (buf, ubuf, count))
    // Devuelve 0 si ha salido bien --> sino => devuelve nº de bytes que no se han podido copiar
    return -EFAULT;		// en userland => errno = EFAULT, “Bad address”

  // Parsear descriptor de fichero que le pasa el user (fd) en forma de string
  // kstrtoint(str, base, &res) --> convierte string a int => devulve 0 en éxito => res contiene el valor convertido => str/buf en memoria del kernel
  // kstrtoint_from_user(ubuf, count, base, &res) --> convierte string a int desde memoria de user (igual pero desde ubuf)
  if (kstrtoint(buf, 10, &fd_aux)) {
    // No se pudo convertir nada
    return -EINVAL;   // errno = invalid argument
  }

  // Asignamos la variable que hemos extraído:
  fd = fd_aux;

  // c = longitud del string "buf" copiado de "ubuf" sin contar '\0'
  c = strlen (buf);
  printk (KERN_DEBUG "write to /proc/mydev: written %d bytes from the user\n",
	  c);

  // Cambiar el puntero de seguimiento/entrada de escritura del fichero "/proc/mydev" al último char copiado
  // Y devolver la posición por donde se encuentra el fichero = nº de bytes hemos recibido del user
  *ppos = c;
  return c;
}

// Se ejecuta al leer en /proc/mydev desde espacio de user
static ssize_t
myread (struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
  // Variables locales:
  char buf[BUFSIZE];		// Array de chars con el tamaño del buffer (100) -> buffer/memoria temporal en stack del kernel (respuesta para espacio de user)
  int len = 0;			// Numero bytes escritos en buf

  // Ver si es la primera vez que se llama a "read" para este fichero --> sino EOF => semántica single-shot 
  // *ppos > 0 --> puntero de posición es mayor que 0 = se ha leído algo ya dentro del fichero /proc/mydev
  // count < BUFSIZE --> tamaño que el user pide leer (count) menor que el buffer definido (100 bytes)
  if (*ppos > 0 || count < BUFSIZE)
    return 0;			// Si se cumple una de las dos --> devolver EOF (0)

  // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se lea en "mydev" --> Loggea
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
  printk (KERN_DEBUG "read from /proc/mydev: read %d bytes to the user\n",
	  len);
  return len;			// > 0 (se han leído bytes) | = 0 (EOF) | < 0 (error)
}

// Tabla de operaciones del fichero creado "mydev"
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
  printk (KERN_INFO "Creating new proc file: /proc/mydev\n");
  ent = proc_create ("mydev", 0660, NULL, &myops);
  // Comprobar errores -> si falla => ent==NULL => deberia devolver -ENOMEM 
  if (!ent)
    return -ENOMEM;
  return 0;
}

// Descargar LKM:
// Borrar referencia/entrada al fichero creado "mydev" en /proc
static void
simple_cleanup (void)
{
  printk (KERN_INFO "Delating proc file: /proc/mydev\n");
  proc_remove (ent);
}

module_init (simple_init);
module_exit (simple_cleanup);
