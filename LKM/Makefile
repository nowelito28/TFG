SEALFS_VERSION="0.91"		# Variable de versión para LKM

# Añade una flag/opción extra al compilador (gcc) cuando compile los .c:
# EXTRA_CFLAGS += -DSEALFS_VERSION=\"$(SEALFS_VERSION)\"		# Define un macro de preprocesador (SEALFS_VERSION) con el valor "0.91" --> Problemas!!!
EXTRA_CFLAGS += -DSEALFS_VERSION=\"0.91\" 
# En C (.c cargado) -> printk(KERN_INFO "Versión: %s\n", SEALFS_VERSION); => imprimirá “Versión: 0.91” en los logs del kernel

# Nombre del módulo principal .c a compilar con kbuild --> .ko:
# CAMBIAR PARA EL NOMBRE DE CADA MÓDULO!!
obj-m += crypto_fd.o

# Indicar al compilador (gcc) -> módulo compuesto por múltiples ficheros objeto (NO solo el principal)
# sealfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

# 1. Cambia al directorio de compilación del kernel en uso -> make -C /lib/modules/$(shell uname -r)/build
# 2. Indica al sistema de compilación del kernel que compile el Makefile local en el directorio actual (pwd) -> M=$(shell pwd)
# 3. Especifica que compile módulos externos -> modules
all: k_embedded.h
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

# Limpia todos los archivos intermedios que haya creado (*.o, *.mod.c, *.symvers, etc.) -> directorio limpio
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

# Indica que all y clean no son archivos, sino targets “falsos” -> Para no confundir por ficheros del mismo nombre
.PHONY: all clean