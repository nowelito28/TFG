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
enum { LEN = 4096 };

// Separador y longitud -> detectar al leer línea a línea:
const char sep[] = "-HMAC(SHA-256)-\n";
const int sep_len = sizeof (sep) - 1;	// NO contar '\0'


// Leer de FILE hasta encontrar separador -> leer LEN bytes max arbitrários
void read_until_separator (FILE *f, char **content, int *content_len)
{
    char *line = NULL;
    size_t cap = 0;
    int len = 0;

    int sep_found = 0;

    int *content_len = 0;
    char **content = (char *) malloc(LEN);
    if (!(*content)) {
        warnx("malloc failed for the content\n");
        goto err_fhandoff;
    }

    while ((len = getline(&line, &cap, f)) != 1) {

        if (strcmp(line, sep) == 0) {
            sep_found = 1;
            break;
        }

        if (*content_len + len > LEN) {
            free(line);
            warnx("Content read exceeds 4KB buffer before separator\n");
            goto free_cont;
        }

        memcpy(*content + *content_len, line, len);
        *content_len += len;
    }

    free(line);

    if (len == -1) {
        warnx("Lines reading with buffering failed\n");
        goto free_cont;
    }

    if (*content_len > 0 && *content[*content_len - 1] == '\n') {
        *content_len--;
    }

    if (!sep_found) {
        warnx("Separator not found\n");
        goto free_cont;
    }
}


// Leer de FILE HMAC(Base64) en la última línea
void read_hmac_line (FILE *f, char **hmac_b64)
{
    int hmac_b64_len = 0;
    size_t cap = 0;

    hmac_b64_len = getline(hmac_b64, &cap, f);
    if (hmac_b64_len == -1) {
        warnx("Error reading HMAC\n");
        goto free_cont;
    }
}


// Extraer contenido y HMAC(Base64) del fichero stream dado (fhandoff)
void extract_data (FILE *fhandoff, char **content, char **hmac_b64)
{
    int content_len;

    // 1) Extraer Contenido hasta el Separador
    read_until_separator(fhandoff, content, &content_len);

    // 2) Extraer HMAC(Base64) en la última línea
    read_hmac_line(fhandoff, hmac_b64);
}


// Calcular el HMAC(SHA-256) del contenido con la clave K embebida
void calculate_hmac(const char *content, int content_len,
                 unsigned char **hmac_calc, unsigned int *hmac_calc_len)
{
    if (!HMAC (EVP_sha256 (), K, K_len, content, content_len, *hmac_calc, hmac_calc_len)) {
        warnx("HMAC calculation failed\n");
        goto free_all;
    }
}


// Codificar a Base64 el HMAC calculado (ASCII)
void encode_base64(const unsigned char *hmac_calc, unsigned int hmac_calc_len,
                  char **hmac_b64_calc, int *hmac_b64_calc_len)
{
    *hmac_b64_calc_len = EVP_ENCODE_LENGTH (hmac_calc_len);
    *hmac_b64_calc = (unsigned char *) malloc (hmac_b64_calc_len + 1);
    if (!hmac_b64_calc) {
        warnx("malloc failed for HMAC encoded in base 64\n");
        goto free_all;
    }

    *hmac_b64_calc_len = EVP_EncodeBlock (*hmac_b64_calc, hmac_calc, hmac_calc_len);
    if (*hmac_b64_calc_len <= 0) {
        warnx("EVP_EncodeBlock failed or returned zero length");
        goto free_all;
    }
}


// Calcular HMAC(SHA-256) con clave K embebida y codificar a Base64
void calc_and_encode_hmac(const char *content, int content_len, 
                        char **hmac_b64_calc, int **hmac_b64_calc_len)
{
    unsigned char *hmac_calc[EVP_MAX_MD_SIZE];
    unsigned int hmac_calc_len = 0;

    calculate_hmac((const unsigned char *)content, content_len, &hmac_calc, &hmac_calc_len);

    encode_base64(hmac_calc, hmac_calc_len, hmac_b64_calc, hmac_b64_calc_len);
}


// Comprobar HMAC extraída y calculada son iguales
void verify_hmac(const char *hmac_b64, int hmac_b64_len,
                const char *hmac_b64_calc, int hmac_b64_calc_len)
{
    if (CRYPTO_memcmp (hmac_b64_calc, hmac_b64, hmac_b64_calc_len)) {
        warnx("HMAC verification failed: Invalid HMAC\n");
        goto free_all;
    }

    printf("HMAC verification successful: Valid HMAC\n");
}


// Comprobar que el HMAC(SHA-256) calculado del kernel es el correcto
int main (int argc, char *argv[])
{
    if (argc != 2) {
        errx (EXIT_FAILURE, "Usage: %s <path_file_handoff>\n"
            "e.g.: %s ./file_handoff", argv[0], argv[0]);
    }
    const char *path_fhandoff = argv[1];

    // 1) Abrir un fichero stream para poder leer con buffering línea a línea (offset compartido)
    FILE *fhandoff = fopen(path_fhandoff, "r");
    if (!fhandoff) {
        warnx("fopen failed\n");
        goto err_fhandoff;
    }

    // 2) Extraer el contenido del fichero:
    char *content = NULL;
    int content_len = 0;

    char *hmac_b64 = NULL;
    int hmac_b64_len = 0;

    extract_data(fhandoff, &content, &hmac_b64);
    fclose (fhandoff);

    content_len = sizeof(content);
    hmac_b64_len = sizeof(hmac_b64);

    printf ("Extracted content:\n%s\n", content);
    printf ("Extracted HMAC(Base64):\n%s\n", hmac_b64);


    // 3) Calcular HMAC(SHA-256) del contenido y codificarlos a base 64:
    unsigned char *hmac_b64_calc = NULL;
    int hmac_b64_calc_len = 0;

    if (calc_and_encode_hmac(content, content_len, &hmac_b64_calc, &hmac_b64_calc_len)) {
        warnx("HMAC calculation and/or encoding failed\n");
        goto free_all;
    }

    free(content);
    content = NULL;

    // 4) Comparar HMAC(Base64) leída del fichero con el HMAC(Base64) calculado:
    verify_hmac(hmac_b64, hmac_b64_len, hmac_b64_calc, hmac_b64_calc_len);

    free(hmac_b64);
    free(hmac_b64_calc);

    exit(EXIT_SUCCESS);


free_all:
    if (hmac_b64_calc) {
        free(hmac_b64_calc);
    }
    if (hmac_b64) {
        free(hmac_b64);
    }
free_cont:
    if (content) {
        free(content);
    }

err_fhandoff:
    if (fhandoff) {
        fclose(fhandoff);
    }
    
    exit(EXIT_FAILURE);
}
