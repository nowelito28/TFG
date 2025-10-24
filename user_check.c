#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// const unsigned char K[]; const unsigned int K_len;
#include "./LKM/k_embedded.h"

// Valor de 4KB arbitrario (espacio suficiente) -> leer resultado del kernel
enum
{ LEN = 4096 };

// Separador y longitud -> detectar al leer línea a línea:
const char sep[] = "-HMAC(SHA-256)-\n";
const int sep_len = sizeof (sep) - 1;	// NO contar '\0'


// Comprobar que el HMAC(SHA-256) calculado del kernel es el correcto
int main (int argc, char *argv[])
{
  if (argc != 2) {
    errx (EXIT_FAILURE, "Usage: %s <path>\n"
        "e.g.: %s ./file_handoff", argv[0], argv[0]);
  }
  const char *path = argv[1];

  // 1) Descriptor de fichero (fd) --> se abre con todos los permisos:
  int fd = open (path, O_RDWR, 0666);
  if (fd < 0) {
    err (EXIT_FAILURE, "Error opening the file %s", path);
  }

  // 2) Crear un fichero stream para poder leer con buffering línea a línea (offset compartido)
  // cuando -> fclose(fp) => se cerrará también 'fd' -> porque fp posee el descriptor 'fd'
  FILE *stream = fdopen(fd, "r");
  if (!stream) {
    close (fd);
    err (EXIT_FAILURE, "fdopen failed\n");
  }

  // 3) Leer línea a línea hasta encontrar línea con el separador y guardar contenido (max 4KB)
  // Quitar el último '\n' del contenido leído -> lo poner el módulo para poder separar el contenido del separador:
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  int sep_found = 0;

  int content_len = 0;
  char *content = (char *) malloc(LEN);
  if (!content) {
    fclose (stream);
    err (EXIT_FAILURE, "Separator not found\n");
  }

  while ((len = getline(&line, &cap, stream)) != 1) {

    if (strcmp(line, sep) == 0) {
      sep_found = 1;
      break;
    }

    if (content_len + len > LEN) {
      free(line);
      free(content);
      fclose (stream);
      err (EXIT_FAILURE, "Content read exceeds 4KB buffer before separator\n");
    }

    memcpy(content + content_len, line, len);
    content_len += len;
  }

  free(line);

  if (len == -1) {
    free(content);
    fclose (stream);
    err (EXIT_FAILURE, "Lines reading with buffering failed\n");
  }

  if (content_len > 0 && content[content_len - 1] == '\n') {
    content_len--;
  }

  // 4) Comprobar que se ha encontrado el separador y obtener el HMAC en base 64 en la última línea:
  char* hmac_b64 = NULL;
  int hmac_b64_len = 0;

  if (!sep_found) {
    free(content);
    fclose (stream);
    errx (EXIT_FAILURE, "Separator not found\n");
  }

  hmac_b64_len = getline(&hmac_b64, &cap, stream);
  if (hmac_b64_len == -1) {
    free(content);
    fclose (stream);
    err (EXIT_FAILURE, "Lines reading with buffering failed\n");
  }

  printf ("Extracted content:\n%s\n", content);
  printf ("Extracted HMAC(Base64):\n%s\n", hmac_b64);

  // 5) Calcular HMAC(SHA-256) del contenido leído con la clave K embebida --> openssl:
  unsigned char hmac[EVP_MAX_MD_SIZE];
  unsigned int hmac_len = 0;

  if (!HMAC (EVP_sha256 (), K, K_len, (const unsigned char *)content, content_len, hmac, &hmac_len)) {
    free(hmac_b64);
    fclose (stream);
    errx (EXIT_FAILURE, "HMAC(EVP_sha256) failed\n");
  }

  free(content);

  // 6) Codificar HMAC calculado a Base64 (ASCII):
  unsigned int hmac_bs64_calc_len = EVP_ENCODE_LENGTH (hmac_len);
  unsigned char *hmac_b64_calc = (unsigned char *) malloc (hmac_bs64_calc_len + 1);
  if (!hmac_b64_calc) {
    free(hmac_b64);
    fclose (stream);
    errx (EXIT_FAILURE, "malloc failed for hmac_b64_calc\n");
  }

  int real_calc_len = EVP_EncodeBlock (hmac_b64_calc, hmac, hmac_len);

  // 7) Comparar HMAC(Base64) leído del fichero con el HMAC(Base64) calculado -> como cadena de caracteres:
  int ok = CRYPTO_memcmp (hmac_b64_calc, hmac_b64, real_calc_len) == 0; 

  if (!ok) {
    fprintf(stderr, "[calc:%d] '%s'\n[file:%d] '%s'\n", real_calc_len, hmac_b64_calc, hmac_b64_len, hmac_b64);
    free(hmac_b64);
    free(hmac_b64_calc);
    fclose(stream);
    errx(EXIT_FAILURE, "HMAC verification failed: Invalid HMAC\n");
  }
  printf("HMAC verification successful: Valid HMAC\n");

  // 8) Cerrar stream y liberar memoria:
  free(hmac_b64);
  free(hmac_b64_calc);
  fclose (stream);

  exit (EXIT_SUCCESS);
}
