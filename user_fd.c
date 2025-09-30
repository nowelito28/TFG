#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Crear fichero de texto desde el que se pasará el descriptor (fd)
int main(int argc, char *argv[]) {

    // Nombre del fichero a crear
    char *path = "./file_handoff";
    //Nombre del fichero de /proc
    char proc_path[] = "/proc/mydev";

    // Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0666);      // NO LO HEMOS CERRADO!!!
    if (fd == -1) {
        err(EXIT_FAILURE, "Error opening/creating the file");
    }

    // Abrir el fichero de /proc (/proc/mydev):
    int fd_proc = open(proc_path, O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "Error opening %s", proc_path);
	}

    // Convertir el fd (int) a string para escribirlo en /proc/mydev
    char fd_str[12];    // Suficiente para un integer
    snprintf(fd_str, sizeof(fd_str), "%d", fd);   // ej: 57 --> "57"

    // Escribir en el fichero de /proc (/proc/mydev) el fd del fichero creado (file_handoff):
    if (write(fd_proc, fd_str, strlen(fd_str)) < 0) {
        close(fd_proc);
        err(EXIT_FAILURE, "Error writing in %s", proc_path);
    }
    printf("File descriptor written in /proc/mydev:\n%s\n", fd_str);

    // Cerrar el fichero de /proc
    close(fd_proc);

    exit(EXIT_SUCCESS);
} 