#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>

// Asegurarnos que se realiza la lectura completa: (return -1 en error)
static int read_full(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, (unsigned char*)buf + off, len - off);
        if (r < 0) {
            if (errno == EINTR) {   // reintentar si fue interrumpido
                continue;
            }
            return -1;
        }
        if (r == 0) {   // EOF inesperado
            break;
        }
        off += (size_t)r;   // Sumar el offset ya leído
    }
    return (off == len) ? 0 : -1;   // Devolver 0 si se ha leído lo pedido o -1 en otro caso
}

// Asegurarnos que hace la lectura completa:    (return -1 en error)
static int write_full(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const unsigned char*)buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {   // reintentar si fue interrumpido
                continue;
            }
            return -1;
        }
        off += (size_t)w;   // Sumar el offset ya escrito
    }
    return 0;       // Devolver 0 en caso de haber escrito lo pedido
}

// Crear fichero de texto desde el que se pasará el descriptor (fd)
int main(int argc, char *argv[]) {

    // Nombre del fichero a crear
    char *path = "./file_handoff";
    // Nombre del fichero de /proc donde escribir el fd de file_handoff
    char proc_path_fd[] = "/proc/fddev";
    // Nombre del fichero de /proc donde escribir el contenido a escribir contenido firmado con HMAC en el fd de file_handoff
    char proc_path_hmac[] = "/proc/hmacdev";

    // Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (fd < 0) {
        err(EXIT_FAILURE, "Error opening/creating the file");
    }

    // Abrir el fichero de /proc (/proc/fddev):
    int fd_proc = open(proc_path_fd, O_RDWR);
	if (fd_proc < 0) {
		err(EXIT_FAILURE, "Error opening %s", proc_path_fd);
	}

    // Abrir el fichero de /proc (/proc/hmacdev):
    int fd_proc_hmac = open(proc_path_hmac, O_RDWR);
	if (fd_proc_hmac < 0) {
		err(EXIT_FAILURE, "Error opening %s", proc_path_hmac);
	}

    // Convertir el fd (int) a string para escribirlo en /proc/fddev
    char fd_str[12];    // Suficiente para un integer
    snprintf(fd_str, sizeof(fd_str), "%d", fd);   // ej: 57 --> "57"

    // Escribir en el fichero de /proc (/proc/fddev) el fd (en string sin el '/0') del fichero creado (file_handoff):
    if (write_full(fd_proc, fd_str, strlen(fd_str)) != 0) {
        close(fd_proc);
        err(EXIT_FAILURE, "Error writing in %s", proc_path_fd); 
    }
    printf("File descriptor written in /proc/fddev:\n%s\n", fd_str);

    // Escribir en el fichero de /proc (/proc/hmacdev) el contenido a escribir en el fd (file_handoff) firmado con HMAC
    char cont[] = "This is an authentic content, validated by HMAC(SHA-256)!!\n";
    if (write_full(fd_proc_hmac, cont, strlen(cont)) != 0) {
        close(fd_proc_hmac);
        err(EXIT_FAILURE, "Error writing in %s", proc_path_hmac); 
    }
    printf("Content certificated written through /proc/hmacdev:\n%s\n", cont);

    // Ver el contenido del fichero creado (file_handoff) con su certificado HMAC(SHA-256) (Base64):
    printf("Content of the created file (%s):\n", path);
    char result[strlen(cont) + 100]; // Buffer para leer el contenido del fichero creado (con espacio extra para el HMAC en Base64)
     // Leer más bytes para incluir el HMAC (Base64) --> con 100 bytes extras da de sobra para el HMAC de clave simétrica SHA-256 (32bytes) -> 44 caracteres aprox en Base64 + '\0')
    if (read_full(fd, result, strlen(cont) + 100) != 0) {
        err(EXIT_FAILURE, "Error reading from %s", path);
        close(fd);
    }
    printf("%s\n", result);

    // Cerrar el fichero de /proc --> /proc/fddev
    close(fd_proc);

    // Cerrar el fichero de /proc --> /proc/hmacdev
    close(fd_proc_hmac);

    // Cerrar el fichero creado (file_handoff)
    close(fd);

    exit(EXIT_SUCCESS);
} 