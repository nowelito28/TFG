#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void main(void)
{
    // Buffer (string) reservado para leer del fichero "/proc/mydev"
	char buf[100];
    // Abrir el archivo virtual que creó tu LKM en /proc con permisos de lectura y escritura
	int fd = open("/proc/mydev", O_RDWR);
    // Leer 100 bytes (buf) de "/proc/mydev" desde el user
	read(fd, buf, 100);
    // puts --> Imprime la cadena de caracteres "buf" en la salida estándar (stdout)
	puts(buf);

    // Resetear posición a 0 en "/proc/mydev"
	lseek(fd, 0 , SEEK_SET);
    // Escribir 2 número en un mismo string en "/proc/mydev"
	write(fd, "33 4", 5);
	
    // Resetear posición a 0 en "/proc/mydev"
	lseek(fd, 0 , SEEK_SET);
    // Volver a leer 100 bytes (buf) de "/proc/mydev" desde el user
	read(fd, buf, 100);

	puts(buf);
}	