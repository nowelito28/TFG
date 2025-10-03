#include <linux/module.h>
#include <linux/moduleparam.h>	// Cabeceras del kernel
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kstrtox.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/string.h>

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
  const char *payload = "Hello, world!\n";  // Payload (en memoria del kernel)--> lo que se va a escribir en el fichero correspondiente al fd que nos pasa el user

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

// IMPLEMENTAR AQUÍ: ESCRIBIR HOLA MUNDO EN EL FICHERO CORRESPONDIENTE AL DESCRIPTOR DE FICHERO "fd"
    // struct fd f = fdget() --> para convertir el entero fd (descriptor de fichero dado) en struct fd "f" (igual que ksys_write)(si es válido en ESTE proceso)
    // fdget(fd) <--> fput(f) => SIEMPRE
    struct fd f = fdget(fd);
    // written --> nº bytes escritos en "f" (o error <0 --> en kernel_write)
    ssize_t written;
    // Posición de escritura (si aplica --> posicional/regular SI | stream NO)
    loff_t pos, *ppos_f;

    // Comprobar que el fd es válido en ESTE proceso --> f.file != NULL
    if (!f.file)
        return -EBADF;  // fd inválido en ESTE proceso --> errno = bad file descriptor

    // Igual que ksys_write: trabajar con copia de f_pos si aplica
    // file_ppos(f.file) decide cómo gestionar la posición:
    //  - regular/posicional file --> devuelve puntero a f_pos => posición actual del fichero (ppos_f apunta a &f.file->f_pos, porque ppos_f es puntero)
    //  - stream (socket, pipe, etc.) --> devuelve NULL (ppos_f = NULL)
    ppos_f = file_ppos(f.file);
    if (ppos_f) {       // si es fichero posicional/regular
      // Ambas variables hacerlas iguales --> que apunten a la misma dirección de memoria
        pos = *ppos_f;  // guardar copia de la posición actual en pos
        ppos_f = &pos;  // ppos_f apunta a la dirección de memoria de la copia (pos) para usar en kernel_write (en memoria del kernel)
    }

    // Iniciamos escritura desde memoria del kernel (payload) al fichero "f.file" (fd recibido)
    // Utilizamos kernel_write (internamente llama a rw_verify_area(...), hace file_start_write(...) / file_end_write(...), y delega en __kernel_write --> write_iter)
    // NO usar vfs_write --> porque se utiliza para camino de syscall (user->kernel) => utiliza memoria de userspace (ubuf) --> si utiliza memoria del kernel => -EFAULT (fallo de acceso a memoria)
    written = kernel_write(f.file, payload, strlen(payload), ppos_f); // ssize_t kernel_write(struct file *file(fichero), const char *buf(buffer en memoria del kernel), size_t count(nº bytes a escribir de buf), loff_t *pos);

    // Si acaba en éxito kernel_write (written >= 0 --> written <0 => error)
    // y es fichero posicional/regular NO stream (ppos_f != NULL)
    // Actualizar f_pos real a la posición nueva actual tras haber escrito strlen(payload) bytes -->(pos) en f.file->f_pos
    if (written >= 0 && ppos_f)
        f.file->f_pos = pos;

    // Liberar struct fd "f" (decrementar contador de referencias y suelta cualquier estado asociado a la posición)
    fdput(f);

    // En caso de error en kernel_write --> written < 0:
    if (written < 0)
        return written;  // propagar error (-EBADF, -EFAULT, etc.)
/////////

    // written --> nº bytes escritos en el fichero correspondiente al fd que nos ha pasado el user
    printk(KERN_DEBUG "write to fd %d: written %zd bytes\n", fd, written);

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
