#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>

// Asegurarnos que se realiza la lectura completa: (return -1 en error)
static int
read_full (int fd, void *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t r = read (fd, (unsigned char *) buf + off, len - off);
      if (r < 0)
	{
	  if (errno == EINTR)
	    {			// reintentar si fue interrumpido
	      continue;
	    }
	  return -1;
	}
      if (r == 0)
	{			// EOF antes del final pedido (EOF antes de leer len bytes)
	  return 0;
	}
      off += (size_t) r;	// Sumar el offset ya leído
    }
  return (off == len) ? 0 : -1;	// Devolver 0 si se ha leído lo pedido o -1 en otro caso
}

// Asegurarnos que hace la lectura completa:    (return -1 en error)
static int
write_full (int fd, const void *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t w = write (fd, (const unsigned char *) buf + off, len - off);
      if (w < 0)
	{
	  if (errno == EINTR)
	    {			// reintentar si fue interrumpido
	      continue;
	    }
	  return -1;
	}
      off += (size_t) w;	// Sumar el offset ya escrito
    }
  return 0;			// Devolver 0 en caso de haber escrito lo pedido
}

// Crear fichero de texto desde el que se pasará el descriptor (fd)
int
main (int argc, char *argv[])
{

  // Nombre del fichero a crear
  char *path = "./file_handoff";
  // Nombre del fichero de /proc donde escribir el fd de file_handoff
  char proc_path_fd[] = "/proc/fddev";

  // Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos
  int fd = open (path, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd < 0)
    {
      err (EXIT_FAILURE, "Error opening/creating the file %s", path);
    }

  // Abrir el fichero de /proc (/proc/fddev):
  int fd_proc = open (proc_path_fd, O_RDWR);
  if (fd_proc < 0)
    {
      err (EXIT_FAILURE, "Error opening %s", proc_path_fd);
    }

  // Convertir el fd (int) a string para escribirlo en /proc/fddev
  char fd_str[12];		// Suficiente para un integer
  snprintf (fd_str, sizeof (fd_str), "%d", fd);	// ej: 57 --> "57"

  // Escribir en el fichero creado (file_handoff) el contenido ser certificado con HMAC(SHA 256):
  char cont[] = "This is an authentic content to be validated by HMAC(SHA-256)!!";
  if (write_full (fd, cont, strlen (cont)) != 0)
    {
      close (fd_proc);
      close (fd);
      err (EXIT_FAILURE, "Error writing in %s", path);
    }
  printf ("Content certificated with HMAC(SHA-256):\n%s\n", cont);

  // Escribir en el fichero de /proc (/proc/fddev) el 'fd' (sin el '/0') del fichero creado (file_handoff) y que será certificado su contenido:
  if (write_full (fd_proc, fd_str, strlen (fd_str)) != 0)
    {
      close (fd_proc);
      close (fd);
      err (EXIT_FAILURE, "Error writing in %s", proc_path_fd);
    }
  printf ("File descriptor written in /proc/fddev:\n%s => Content has been certificated.\n", fd_str);

  // Ver el contenido del fichero creado (file_handoff) con su certificado HMAC(SHA-256) (Base64):
  printf ("Content of the created file (%s):\n", path);
  size_t len = strlen (cont) + 100;
  char *result = (char *) malloc (len);	// Buffer para leer el contenido del fichero creado (con espacio extra para el HMAC en Base64)
  // Recoloca el puntero de fichero al principio antes de leer --> debido a que la posición actual está al final del fichero al haber escrito el LKM en él
  if (lseek (fd, 0, SEEK_SET) == (off_t) - 1)
    {
      close (fd_proc);
      close (fd);
      err (EXIT_FAILURE, "lseek to start failed on %s", path);
    }
  // Leer más bytes para incluir el HMAC (Base64) --> con 100 bytes extras da de sobra para el HMAC de clave simétrica SHA-256 (32bytes) -> 44 caracteres aprox en Base64 + '\0')
  if (read_full (fd, result, len) != 0)
    {
      close (fd_proc);
      close (fd);
      free (result);
      err (EXIT_FAILURE, "Error reading from %s", path);
    }
  printf ("%s\n", result);
  free (result);

  // Cerrar el fichero de /proc --> /proc/fddev
  close (fd_proc);

  // Cerrar el fichero creado (file_handoff)
  close (fd);

  exit (EXIT_SUCCESS);
}
