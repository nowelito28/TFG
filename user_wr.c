#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// const unsigned char K[]; const unsigned int K_len;
#include "./LKM/k_embedded.h"

// Valor de 4KB arbitrario de prueba -> leer resultado del kernel
enum
{ LEN = 4096 };

// Separador y longitud -> detectar al leer línea a línea:
const char sep[] = "-HMAC(SHA-256)-\n";
const int sep_len = sizeof (sep) - 1;	// NO contar '\0'

// Asegurarnos que se realiza la lectura completa: 
// Devuelve bytes leídos (>0 -> puede ser <len) <-> -1 en error
static int read_full (int fd, unsigned char *buf, int len)
{
  int off = 0;
  int r;

  while (off < len) {
    r = read (fd, buf + off, len - off);

    if (r < 0) {

      if (errno == EINTR)	// reintentar si es interrumpido
        continue;

      return -1;
    }

    if (r == 0)
      break;  // EOF encontrado

    off += r;
  }

  return off;
}

// Asegurarnos que se realiza la escritura completa: 
// Devuelve bytes escritos (>0 -> puede ser <len) <-> -1 en error
static int
write_full (int fd, const char *buf, int len)
{
  int off = 0;
  int w;

  while (off < len) {
    w = write (fd, buf + off, len - off);

    if (w < 0) {

      if (errno == EINTR)	// reintentar si fue interrumpido     
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
  char path[] = "./file_handoff";
  char proc_path[] = "/proc/fddev";

  // 1) Descriptor de fichero (fd) --> lo crear y si existe => lo trunca (vacía) --> se abre con todos los permisos:
  int fd = open (path, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd < 0) {
    err (EXIT_FAILURE, "Error opening/creating the file %s", path);
  }

  // 2) Abrir el fichero de /proc (/proc/fddev):
  int fd_proc = open (proc_path, O_RDWR);
  if (fd_proc < 0) {
    err (EXIT_FAILURE, "Error opening %s", proc_path);
  }

  // 3) Convertir el fd (int) a string para escribirlo en /proc/fddev
  char fd_str[12];
  snprintf (fd_str, sizeof (fd_str), "%d", fd);

  // 4) Escribir en el fichero de /proc (/proc/fddev) el 'fd' (sin el '/0') del fichero creado (file_handoff):
  // Cerrar descriptor de fichero de /proc ya que no lo necesitamos más
  if (write_full (fd_proc, fd_str, strlen (fd_str)) <= 0) {
    close (fd_proc);
    close (fd);
    err (EXIT_FAILURE, "Error writing in %s", proc_path);
  }
  printf ("File descriptor written in /proc/fddev:\n%s\n", fd_str);
  close(fd_proc);

  // 5) Mover puntero de lectura al inicio del fichero y reservar memoria para el contenido del fichero (1KB)
  // Ver el contenido certificado que nos ha escrito el kernel en (file_handoff -> fd) 
  // poner puntero de lectura al inicio y leer con buffering línea a línea hasta encontrar el separador
  // y dividir el contenido y el HMAC(SHA-256)(Base64):
  printf ("Content dispatched by kernel in ./file_handoff(%s):\n", path);

  int result_len;
  unsigned char *result = (unsigned char *) malloc (LEN);
  if (!result) {
    close (fd);
    err (EXIT_FAILURE, "malloc failed\n");
  }

  if (lseek (fd, 0, SEEK_SET) == -1) {
    close (fd);
    free (result);
    err (EXIT_FAILURE, "lseek to start failed on %s", path);
  }

  //volver hacer el write full para mostrar contenido

  // 6) Crear un fichero stream para poder leer con buffering línea a línea (offset compartido)
  // cuando -> fclose(fp) => se cerrará también 'fd' -> porque fp posee el descriptor 'fd'
  FILE *fp = fdopen(fd, "r");
  if (!fp) {
    close (fd);
    err (EXIT_FAILURE, "fdopen failed\n");
  }

  // 7) Leer línea a línea hasta encontrar línea con el separador y guardar contenido (max 4KB):
  char *line = NULL;
  int cap, len = 0;

  int sep_found = 0;

  int content_len = 0;
  char *content = (char *) malloc(LEN);
  if (!content) {
    fclose (fp);
    err (EXIT_FAILURE, "Separator not found\n");
  }

  while ((len = getline(&line, &cap, fp)) != 1) {

    if (strcmp(line, sep) == 0) {
      sep_found = 1;
      break;
    }

    if (content_len + len > LEN) {
      fclose (fp);
      err (EXIT_FAILURE, "Content read exceeds 4KB buffer before separator\n");
    }

    memcpy(content + content_len, line, len);
    content_len += len;
  }

  if (len == -1) {
    fclose (fp);
    err (EXIT_FAILURE, "Lines reading with buffering failed\n");
  }

  // 8) Comprobar que se ha encontrado el separador y obtener el HMAC en base 64 en la última línea:
  unsigned char* hmac_b64 = NULL;
  int hmac_b64_len = 0;

  if (!sep_found) {
    fclose (fp);
    err (EXIT_FAILURE, "Separator not found\n");
  }

  hmac_b64_len = getline(&hmac_b64, &cap, fp);
  if (hmac_b64_len == -1) {
    fclose (fp);
    err (EXIT_FAILURE, "Lines reading with buffering failed\n");
  }

  printf ("Extracted content:\n%s\n", content);
  printf ("Extracted HMAC(Base64):\n%s\n", hmac_b64);

  // 9) Calcular HMAC(SHA-256) del contenido leído con la clave K embebida --> openssl:
  unsigned char hmac[EVP_MAX_MD_SIZE];
  unsigned int hmac_len = 0;

  if (!HMAC (EVP_sha256 (), K, K_len, content, content_len, hmac, &hmac_len)) {
    free (result);
    fclose (fp);
    errx (EXIT_FAILURE, "HMAC(EVP_sha256) failed\n");
  }

  // 10) Codificar HMAC calculado a Base64 (ASCII):
  unsigned int hmac_bs64_calc_len = EVP_ENCODE_LENGTH (hmac_len);
  unsigned char *hmac_b64_calc =
    (unsigned char *) malloc (hmac_bs64_calc_len + 1);
  if (!hmac_b64_calc)
    {
      free (result);
      fclose (fp);
      errx (EXIT_FAILURE, "malloc failed for hmac_b64_calc\n");
    }

  int w = EVP_EncodeBlock (hmac_b64_calc, hmac, hmac_len);

  // 11) Comparar HMAC(Base64) leído del fichero con el HMAC(Base64) calculado -> como cadena de caracteres:
  int ok = -1;

  if (w == hmac_b64_len) {
    ok = (CRYPTO_memcmp (hmac_b64_calc, hmac_b64, w) == 0); 
  }
  printf ("HMAC(SHA-256) Base64 bytes compare: %s\n",
	  ok ? "Equal -> valid HMAC" : "Not equal -> invalid HMAC");

  // 12) Cerrar ficheros abiertos y liberar memoria:
  free (result);
  fclose (fp);
  exit (EXIT_SUCCESS);
}
