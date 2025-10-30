#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Valor de 4KB arbitrario de prueba -> leer resultado del kernel
enum { LEN = 4096 };

// Asegurarnos que se realiza la escritura completa: 
// Devuelve bytes escritos (>0 -> puede ser <len) <-> -1 en error
static int write_full (int fd, const char *buf, int len)
{
  int off = 0;
  int w = 0;

  while (off < len) {
    w = write (fd, buf + off, len - off);

    if (w < 0) {
      if (errno == EINTR) // reintentar si fue interrumpido	
        continue;

      return -1;
    }

    off += w;
  }

  return off;
}


// Crear fichero (file_handoff) cuyo fd se lo pasamos al fichero creado en /proc por el LKM
int main (int argc, char *argv[])
{
  if (argc != 3) {
    errx (EXIT_FAILURE, "Usage: %s <common_path> <proc_path>\n"
      "e.g.: %s ./file_handoff /proc/fddev", argv[0], argv[0]);
  }
  const char *f_handoff = argv[1];        // ./file_handoff
  const char *f_proc = argv[2];   //  /proc/fddev

  // 1) Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos:
  int fd_handoff = open (f_handoff, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd_handoff < 0) {
    err (EXIT_FAILURE, "Error opening/creating the file %s", f_handoff);
  }

  // 2) Abrir el fichero de /proc (/proc/fddev):
  int fd_proc = open (f_proc, O_RDWR);
  if (fd_proc < 0) {
    err (EXIT_FAILURE, "Error opening %s", f_proc);
  }

  // 3) Convertir el fd (int) a string para escribirlo en /proc/fddev
  char fd_str[12];
  snprintf (fd_str, sizeof (fd_str), "%d", fd_handoff);

  // 4) Escribir en el fichero de /proc (/proc/fddev) el 'fd' (sin el '/0') del fichero creado (file_handoff):
  // No utilizar buffering (stdio) para ficheros en /proc => conflictos
  if (write_full (fd_proc, fd_str, strlen (fd_str)) <= 0) {
    close (fd_proc);
    close (fd_handoff);
    err (EXIT_FAILURE, "Error writing in %s", f_proc);
  }
  printf("File descriptor written in %s:\n%d\n", f_proc, fd_handoff);

  close (fd_proc);
  close (fd_handoff);

  exit (EXIT_SUCCESS);
}
