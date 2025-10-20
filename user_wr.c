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

// Valor de 1KB arbitrario de prueba -> leer resultado del kernel
enum
{ LEN = 1024 };

// Separador y longitud:
const char sep[] = "\n-HMAC(SHA-256)-\n";
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
  if (write_full (fd_proc, fd_str, strlen (fd_str)) <= 0) {
    close (fd_proc);
    close (fd);
    err (EXIT_FAILURE, "Error writing in %s", proc_path);
  }
  printf ("File descriptor written in /proc/fddev:\n%s\n", fd_str);

  // 5) Ver el contenido certificado que nos ha escrito el kernel en (file_handoff -> fd) con su certificado HMAC(SHA-256)(Base64):
  printf ("Content dispatched by kernel in ./file_handoff(%s):\n", path);

  int result_len;
  unsigned char *result = (unsigned char *) malloc (LEN);
  if (!result) {
    close (fd_proc);
    close (fd);
    err (EXIT_FAILURE, "malloc failed\n");
  }

  if (!result) {
    close (fd_proc);
    close (fd);
    err (EXIT_FAILURE, "malloc failed\n");
  }

  if (lseek (fd, 0, SEEK_SET) == -1) {
    close (fd_proc);
    close (fd);
    free (result);
    err (EXIT_FAILURE, "lseek to start failed on %s", path);
  }

  result_len = read_full (fd, result, LEN);
  if (result_len < 0) {
    close (fd_proc);
    close (fd);
    free (result);
    err (EXIT_FAILURE, "Error reading from %s", path);
  }

  printf ("%s\n", result);

  // 6) Tokenizar conteido leído según el separador para obtener el contenido y el HMAC(Base64) por separado:
  unsigned char *sep_pos = memmem (result, result_len, sep, sep_len);
  if (!sep_pos) {
    free (result);
    close (fd_proc);
    close (fd);
    errx (EXIT_FAILURE, "Separation not found -> No HMAC present in %s\n",
    path);
  }

  // Longitud del contenido antes del separador: diferencia de punteros (distancia)
  const int content_len = (int) (sep_pos - result);
  // HMAC en base64 después del separador (dirección al inicio del HMAC)
  unsigned char *hmac_b64 = sep_pos + sep_len;
  // Borrar contenido desde el separador para tener solo el contenido puro
  *sep_pos = '\0';
  // Contenido antes del separador
  const unsigned char *content = result;
  // Longitud del HMAC en base64 (sin contar '\0')
  unsigned int hmac_b64_len = sizeof (hmac_b64) - 1;

  printf ("Extracted content:\n%s\n", content);
  printf ("Extracted HMAC(Base64):\n%s\n", hmac_b64);

  // 7) Calcular HMAC(SHA-256) del contenido leído con la clave K embebida --> openssl:
  unsigned char hmac[EVP_MAX_MD_SIZE];
  unsigned int hmac_len = 0;

  if (!HMAC (EVP_sha256 (), K, K_len, content, content_len, hmac, &hmac_len)) {
    free (result);
    close (fd_proc);
    close (fd);
    errx (EXIT_FAILURE, "HMAC(EVP_sha256) failed\n");
  }

  // 8) Codificar HMAC calculado a Base64 (ASCII):
  unsigned int hmac_bs64_calc_len = EVP_ENCODE_LENGTH (hmac_len);
  unsigned char *hmac_b64_calc =
    (unsigned char *) malloc (hmac_bs64_calc_len + 1);
  if (!hmac_b64_calc)
    {
      free (result);
      close (fd_proc);
      close (fd);
      errx (EXIT_FAILURE, "malloc failed for hmac_b64_calc\n");
    }

  int w = EVP_EncodeBlock (hmac_b64_calc, hmac, hmac_len);

  // 9) Comparar HMAC(Base64) leído del fichero con el HMAC(Base64) calculado -> como cadena de caracteres:
  int ok = -1;

  if (w == hmac_b64_len) {
    ok = (CRYPTO_memcmp (hmac_b64_calc, hmac_b64, w) == 0);
  }
  printf ("HMAC(SHA-256) Base64 bytes compare: %s\n",
	  ok ? "Equal -> valid HMAC" : "Not equal -> invalid HMAC");

  // 10) Cerrar ficheros abiertos y liberar memoria:
  free (result);
  close (fd_proc);
  close (fd);

  exit (EXIT_SUCCESS);
}
