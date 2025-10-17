#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>

// Asegurarnos que se realiza la lectura completa: 
// Devuelve bytes leídos (>0 -> puede ser <len) <-> -1 en error <-> 0 EOF inesperado
static int
read_full (int fd, char *buf, size_t len)
{
  ssize_t off = 0;
  while (off < len)
  {
    ssize_t r = read (fd, buf + off, len - off);

    if (r < 0)
    {
      if (errno == EINTR) // reintentar si es interrumpido
        continue;
      return -1;
    }
    
    if (r == 0)
      return 0;

    off += r;
  }

  return off;
}

// Asegurarnos que se realiza la escritura completa: 
// Devuelve bytes escritos (>0 -> puede ser <len) <-> -1 en error
static int
write_full (int fd, const char *buf, size_t len)
{
  ssize_t off = 0;
  while (off < len)
  {
    ssize_t w = write (fd, buf + off, len - off);

    if (w < 0)
    {
      if (errno == EINTR) // reintentar si fue interrumpido	
        continue;
      return -1;
    }

    off += w;
  }
  return off;
}


// Crear fichero (file_handoff) cuyo fd se lo pasamos al fichero creado en /proc por el LKM
int
main (int argc, char *argv[])
{
  char path[] = "./file_handoff";
  char proc_path[] = "/proc/fddev";

  // 1) Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos:
  int fd = open (path, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd < 0)
    {
      err (EXIT_FAILURE, "Error opening/creating the file %s", path);
    }

  // 2) Abrir el fichero de /proc (/proc/fddev):
  int fd_proc = open (proc_path, O_RDWR);
  if (fd_proc < 0)
    {
      err (EXIT_FAILURE, "Error opening %s", proc_path);
    }

  // 3) Convertir el fd (int) a string para escribirlo en /proc/fddev
  char fd_str[12];
  snprintf (fd_str, sizeof (fd_str), "%d", fd);

  // 4) Escribir en el fichero de /proc (/proc/fddev) el 'fd' (sin el '/0') del fichero creado (file_handoff):
  if (write_full (fd_proc, fd_str, strlen (fd_str)) <= 0)
    {
      close (fd_proc);
      close (fd);
      err (EXIT_FAILURE, "Error writing in %s", proc_path);
    }
  printf ("File descriptor written in /proc/fddev:\n%s\n", fd_str);

  // 5) Ver el contenido certificado que nos ha escrito el kernel en (file_handoff -> fd) con su certificado HMAC(SHA-256)(Base64):
  printf ("Content dispatched by kernel in ./file_handoff(%s):\n", path);

  size_t len = 1024;  // Valor de 1KB arbitrario de prueba con espacio de sobra
  char *result = (char *) malloc (len);
  if (!result)
    {
      close (fd_proc);
      close (fd);
      err (EXIT_FAILURE, "malloc failed\n");
    }

  if (lseek (fd, 0, SEEK_SET) == (off_t) - 1)
    {
      close (fd_proc);
      close (fd);
      free (result);
      err (EXIT_FAILURE, "lseek to start failed on %s", path);
    }

  if (read_full (fd, result, len) < 0)
    {
      close (fd_proc);
      close (fd);
      free (result);
      err (EXIT_FAILURE, "Error reading from %s", path);
    }

  printf ("%s\n", result);
  free (result);

  // 6) Cerrar ficheros abiertos:
  close (fd_proc);
  close (fd);

  exit (EXIT_SUCCESS);
}
