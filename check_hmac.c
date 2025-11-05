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

// Separador entre el contenido del fichero y el contenido del kernel:
const char sep[] = "--KERNEL--\n";

// Separador entre el contenido del kernel y el HMAC en base 64:
const char sep_hmac[] = "--HMAC(SHA-256)--\n";


// Leer de FILE hasta encontrar separador -> leer LEN bytes max arbitrários
// Devuelve 0 en éxito <-> 1 en error
int read_until_separator (FILE *f, char **content, int *content_len)
{
    char *line = NULL;
    size_t cap = 0;
    int len = 0;

    int sep_found = 0;
    int sep_hmac_found = 0;

    *content = (char *) malloc(LEN);
    if (!(*content)) {
        warnx("malloc failed for the content\n");
        return 1;
    }

    while ((len = getline(&line, &cap, f)) != -1) {

        if (!sep_found) {
            if (strcmp(line, sep) == 0) {
                sep_found = 1;
            }
            continue;
        }

        if (strcmp(line, sep_hmac) == 0) {
            sep_hmac_found = 1;
            break;
        }

        if (*content_len + len > LEN) {
            free(line);
            warnx("Content read exceeds 4KB buffer before separator\n");
            return 1;
        }

        memcpy(*content + *content_len, line, len);
        *content_len += len;
    }
    
    free(line);

    if (len == -1) {
        warnx("Lines reading with buffering failed\n");
        return 1;
    }

    if (*content_len > 0 && (*content)[*content_len - 1] == '\n') {
        *content_len -= 1;
    }

    if (sep_hmac_found == 0) {
        warnx("Separator not found\n");
        return 1;
    }

    return 0;
}


// Leer de FILE HMAC(Base64) en la última línea
// Devuelve 0 en éxito <-> 1 en error
int read_hmac_line (FILE *f, char **hmac_b64, int *hmac_b64_len)
{
    size_t cap = 0;

    *hmac_b64_len = getline(hmac_b64, &cap, f);
    if (*hmac_b64_len == -1) {
        warnx("Error reading HMAC\n");
        return 1;
    }

    return 0;
}


// Extraer contenido y HMAC(Base64) del fichero stream dado (fhandoff)
// Devuelve 0 en éxito <-> 1 en error
int extract_data (FILE *fhandoff, char **content, int *content_len, char **hmac_b64, int *hmac_b64_len)
{
    if (read_until_separator(fhandoff, content, content_len) ||
        read_hmac_line(fhandoff, hmac_b64, hmac_b64_len)) {
        printf("errror");
        return 1;
    }

    return 0;
}


// Calcular el HMAC(SHA-256) del contenido con la clave K embebida
// Devuelve 0 en éxito <-> 1 en error
int calculate_hmac(const unsigned char *content, int content_len,
                 unsigned char *hmac_calc, unsigned int *hmac_calc_len)
{
    if (!HMAC (EVP_sha256 (), K, K_len, content, content_len, hmac_calc, hmac_calc_len)) {
        warnx("HMAC calculation failed\n");
        return 1;
    }

    return 0;
}


// Codificar a Base64 el HMAC calculado (ASCII)
// Devuelve 0 en éxito <-> 1 en error
int encode_base64(unsigned char *hmac_calc, unsigned int hmac_calc_len,
                  unsigned char **hmac_b64_calc, int *hmac_b64_calc_len)
{
    *hmac_b64_calc_len = EVP_ENCODE_LENGTH (hmac_calc_len);
    *hmac_b64_calc = (unsigned char *) malloc (*hmac_b64_calc_len + 1);
    if (!hmac_b64_calc) {
        warnx("malloc failed for HMAC encoded in base 64\n");
        return 1;
    }

    *hmac_b64_calc_len = EVP_EncodeBlock (*hmac_b64_calc, hmac_calc, hmac_calc_len);
    if (*hmac_b64_calc_len <= 0) {
        warnx("EVP_EncodeBlock failed or returned zero length");
        return 1;
    }

    return 0;
}


// Calcular HMAC(SHA-256) con clave K embebida y codificar a Base64
// Devuelve 0 en éxito <-> 1 en error
int calc_and_encode_hmac(const char *content, int content_len, 
                        unsigned char **hmac_b64_calc, int *hmac_b64_calc_len)
{
    unsigned char hmac_calc[EVP_MAX_MD_SIZE];
    unsigned int hmac_calc_len = 0;

    if (calculate_hmac((const unsigned char *)content, content_len, hmac_calc, &hmac_calc_len)) {
        return 1;
    }

    if (encode_base64(hmac_calc, hmac_calc_len, hmac_b64_calc, hmac_b64_calc_len)) {
        return 1;
    }

    return 0;
}


// Comprobar HMAC extraída y calculada son iguales
// Devuelve 0 en éxito <-> 1 en error
int verify_hmac(const char *hmac_b64, int hmac_b64_len,
                unsigned char *hmac_b64_calc, int hmac_b64_calc_len)
{
    if (CRYPTO_memcmp (hmac_b64_calc, hmac_b64, hmac_b64_calc_len)) {
        warnx("\nHMAC verification failed: Invalid HMAC\n");
        return 1;
    }

    printf("\nHMAC verification successful: Valid HMAC\n");
    return 0;
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

    if (extract_data(fhandoff, &content, &content_len, &hmac_b64, &hmac_b64_len)) {
        goto free_cont;
    }
    fclose (fhandoff);
    fhandoff = NULL;

    printf ("Extracted kernel content:\n%s\n", content);
    printf ("Extracted HMAC(Base64):\n%s\n", hmac_b64);


    // 3) Calcular HMAC(SHA-256) del contenido y codificarlos a base 64:
    unsigned char *hmac_b64_calc = NULL;
    int hmac_b64_calc_len = 0;

    if (calc_and_encode_hmac(content, content_len, &hmac_b64_calc, &hmac_b64_calc_len)) {
        goto free_all;
    }
    free(content);
    content = NULL;

    printf("Calculated HMAC(Base64): \n%s\n", hmac_b64_calc);

    // 4) Comparar HMAC(Base64) leída del fichero con el HMAC(Base64) calculado:
    int ext = verify_hmac(hmac_b64, hmac_b64_len, hmac_b64_calc, hmac_b64_calc_len);

    free(hmac_b64);
    free(hmac_b64_calc);

    exit(ext);


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
