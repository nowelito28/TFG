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
    // Se notifica en los logs del kernel (/var/log/kern.log) cada vez que se esciba en "mydev" --> Loggea
	printk( KERN_DEBUG "write handler\n");
    // Y sale con estado de error (negativo) => -EPERM (-1)
    // No se guarda/escribe nada 
	return -1;
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