#include <linux/module.h>
#include <linux/moduleparam.h>      // Cabeceras del kernel
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#define BUFSIZE  100  // Constante global

// Metadatos del modulo:
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Noel");

// Puntero de referencia/entrada al fichero que crearemos en /proc
static struct proc_dir_entry *ent;

// Se ejecuta al escribir en /proc/mydev desde espacio de user
static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
    // Variables temporales:
	// num --> nº conversiones que se ha realizado de string a ints
	// c --> última posición de escritura (char) en el fichero "/proc/mydev"
	// i --> primera variable (iq) que se escribe desde el user
	// m --> segunda varibales (mode) que se escribe desde el user
	int num,c,i,m;
	char buf[BUFSIZE];  // Array de chars con el tamaño del buffer (100) -> buffer/memoria temporal en stack del kernel (copiar lo que envía el espacio de user)

    // Ver si es la primera vez que se llama a "write" para este fichero --> sino EOF => semántica single-shot
    // *ppos > 0 --> puntero de posición es mayor que 0 = se ha escrito algo ya dentro del fichero /proc/mydev
	// count <= BUFSIZE --> tamaño que el user pide escribir (count) menor que el buffer definido (100 bytes) --> <= para incluir el '\0'
	if(*ppos > 0 || count <= BUFSIZE)
		return -EFAULT;	// Si se cumple una de las dos --> devolver -EFAULT (dirección user inválida)

	// // Copia "count" bytes desde memoria de espacio de user (ubuf) a memoria del kernel (buf)
	if(copy_from_user(buf,ubuf,count))
		// Devuelve 0 si ha salido bien --> sino => devuelve nº de bytes que no se han podido copiar
		return -EFAULT;  // en userland => errno = EFAULT, “Bad address”

	// Parsear los dos números que se encuentran en "buf" (string) al ser copiados desde "ubuf", en forma de string con un espacio entre medias (misma forma sino falla)
	// --> "i" (iq) y "m" (mode) --> se guardan los valores en sus direcciones
	// sacanf -> devuelve nº conversiones realizadas con éxito (esparamos => num = 2 --> sino -EFAULT => dirección user inválida) 
	num = sscanf(buf,"%d %d",&i,&m);
	if(num != 2)
		return -EFAULT;

	// Asignamos las variables que hemos extraído:
	irq = i; 
	mode = m;

	// c = longitud del string "buf" copiado de "ubuf" sin contar '\0'
	c = strlen(buf);
	// Cambiar el puntero de seguimiento/entrada de escritura del fichero "/proc/mydev" al último char copiado
	// Y devolver la posición por donde se encuentra el fichero = nº de bytes hemos recibido del user
	*ppos = c;
	return c;
}

// Se ejecuta al leer en /proc/mydev desde espacio de user
static ssize_t myread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
    // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se lea en "mydev" --> Loggea
	printk( KERN_DEBUG "read handler\n");
    // Devuelve EOF inmediato (0) --> Lecturas no devuelven nada (No se leera nada)
	return 0;
}

// Tabla de operaciones del fichero creado "mydev"
// Asociar acciones/manejadores que se pueden hacer en este fichero
static struct file_operations myops = 
{
	.owner = THIS_MODULE,  // ayuda al refcount del módulo mientras el archivo este abierto
	.read = myread,
	.write = mywrite,
};

// Cargar LKM:
// Inicializar ent con la creacion del fichero "mydev" en /proc
// con todos los permisos (rw) para el root y el grupo
static int simple_init(void)
{
	ent=proc_create("mydev",0660,NULL,&myops);
    // Comprobar errores -> si falla => ent==NULL => deberia devolver -ENOMEM 
    if (!ent) return -ENOMEM;
	return 0;
}

// Descargar LKM:
// Borrar referencia/entrada al fichero creado "mydev" en /proc
static void simple_cleanup(void)
{
	proc_remove(ent);
}

module_init(simple_init);
module_exit(simple_cleanup);