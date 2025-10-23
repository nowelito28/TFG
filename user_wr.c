#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Valor de 4KB arbitrario de prueba -> leer resultado del kernel
enum
{ LEN = 4096 };


// Crear fichero (file_handoff) cuyo fd se lo pasamos al fichero creado en /proc por el LKM
int main (int argc, char *argv[])
{
  if (argc != 3) {
    errx (EXIT_FAILURE, "Usage: %s <common_path> <proc_path>\n"
      "e.g.: %s ./file_handoff /proc/fddev", argv[0], argv[0]);
  }
  const char *path = argv[1];        // ./file_handoff
  const char *proc_path = argv[2];   //  /proc/fddev

  // 1) Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos:
  // y crear el stream asociado a dicho descriptor de fichero
  int fd = open (path, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd < 0) {
    err (EXIT_FAILURE, "Error opening/creating the file %s", path);
  }

  FILE *stream = fdopen(fd, "r+");
  if (!stream) {
    close(fd);
    err(EXIT_FAILURE, "Error creating stream for %s", path);
  }

  // 2) Abrir el fichero de /proc (/proc/fddev):
  int fd_proc = open (proc_path, O_RDWR);
  if (fd_proc < 0) {
    err (EXIT_FAILURE, "Error opening %s", proc_path);
  }

  FILE *proc_stream = fdopen(fd_proc, "w");
  if (!proc_stream) {
      fclose(stream);
      close(fd_proc);
      err(EXIT_FAILURE, "Error creating stream for %s", proc_path);
  }

  // 3) Convertir el fd (int) a string para escribirlo en /proc/fddev
  char fd_str[12];
  snprintf (fd_str, sizeof (fd_str), "%d", fd);

  // 4) Escribir en el fichero de /proc (/proc/fddev) el 'fd' (sin el '/0') del fichero creado (file_handoff):
  // Cerrar stream y descriptor de fichero de /proc ya que no lo necesitamos más
  if (fwrite(fd_str, 1, strlen(fd_str), proc_stream) != strlen(fd_str)) {
      fclose(proc_stream);
      fclose(stream);
      err(EXIT_FAILURE, "Error writing in %s", proc_path);
  }

  if (fflush(proc_stream) != 0) {   // VER EL ERROR QUE SALE
    fclose(proc_stream);
    fclose(stream);
    err(EXIT_FAILURE, "Error flushing to %s", proc_path);
  }
  
  printf("File descriptor written in %s:\n%s\n", proc_path, fd_str);
  fclose(proc_stream);

  // 5) Mover puntero de lectura al inicio inicio del stream (off = 0 -> SEEK_SET (desde el inicio))
  // reservar memoria para el contenido del fichero (max 4KB) -> mostrar su contenido
  printf ("Content dispatched by kernel in ./file_handoff(%s):\n", path);

  unsigned char *result = (unsigned char *) malloc (LEN);
  if (!result) {
    fclose (stream);
    err (EXIT_FAILURE, "malloc failed\n");
  }

  if (fseek(stream, 0, SEEK_SET) != 0) {
      free(result);
      fclose(stream);
      err(EXIT_FAILURE, "fseek failed on %s", path);
  }

  size_t bytes_r = fread(result, 1, LEN, stream);
  if (bytes_r == 0 && ferror(stream)) {
      free(result);
      fclose(stream);
      err(EXIT_FAILURE, "Error reading from %s", path);
  }

  printf ("%s\n", result);

  // 6) Cerrar streams abiertos y liberar memoria:
  free(result);
  fclose (stream);

  exit (EXIT_SUCCESS);
}
