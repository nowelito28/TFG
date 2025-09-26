#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#define BUFSIZE 100

int main(void)
{
    // Buffer (string) reservado para leer del fichero "/proc/mydev"
	char buf[100];
    // Nombre del fichero creado con el LKM:
    char procfile[] = "/proc/mydev";
	
	// Abrir el archivo virtual en /proc con permisos de lectura y escritura
	int fd = open(procfile, O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "Error opening %s", procfile);
	}

    // Leer el contenido inicial de "/proc/mydev"
    if (read(fd, buf, BUFSIZE) < 0) {
        close(fd);
        err(EXIT_FAILURE, "Error reading from %s", procfile);
    }
    printf("Read inicial content of %s:\n%s", procfile, buf);

    // Resetear posición a 0 en "/proc/mydev"
	if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        err(EXIT_FAILURE, "Lseek error in %s", procfile);
    }

    // Escribir 2 número en un mismo string en "/proc/mydev"
	const char *new_values = "33 4";
    if (write(fd, new_values, strlen(new_values)) < 0) {
        close(fd);
        err(EXIT_FAILURE, "Error writing in %s", procfile);
    }
    printf("Written in /proc/mydev:\n%s\n", new_values);

    // Resetear posición a 0 en "/proc/mydev"
	if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        err(EXIT_FAILURE, "Lseek error in %s", procfile);
    }

    // Volver a leer 100 bytes (buf) de "/proc/mydev" desde el user
	if (read(fd, buf, BUFSIZE) < 0) {
        close(fd);
        err(EXIT_FAILURE, "Error reading from %s", procfile);
    }
    printf("Read updated content from /proc/mydev:\n%s", buf);


	// Cerrar el archivo
    close(fd);
    return EXIT_SUCCESS;
}	