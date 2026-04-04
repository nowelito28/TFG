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

// 40KB (enough space for testing)
enum { LEN = 1024 * 40 };

// Separator between the file content and the kernel content:
const char sep[] = "--KERNEL-PS--\n";

// Separator between kernel content and Base64 HMAC:
const char sep_hmac[] = "--HMAC--\n";

/*
 * Read the file until find the separator -> read LEN bytes at most
 * Return: 0 success <-> 1 error
 */
int read_until_separator(FILE *f, char **content, int *content_len)
{
	char *line = NULL;
	size_t cap = 0;
	int len = 0;

	int sep_found = 0;
	int sep_hmac_found = 0;

	*content = (char *)malloc(LEN);
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
			warnx
			    ("Content read exceeds 4KB buffer before separator\n");
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

/*
 * Read the HMAC(Base64) line (last) from the file:
 * Return: 0 success <-> 1 error
 */
int read_hmac_line(FILE *f, char **hmac_b64, int *hmac_b64_len)
{
	size_t cap = 0;

	*hmac_b64_len = getline(hmac_b64, &cap, f);
	if (*hmac_b64_len == -1) {
		warnx("Error reading HMAC\n");
		return 1;
	}

	return 0;
}

/*
 * Extract the content and HMAC(Base64) form the file stream given (fhandoff):
 * Return: 0 success <-> 1 error
 */
int extract_data(FILE *fhandoff, char **content, int *content_len,
		 	char **hmac_b64, int *hmac_b64_len)
{

	if (read_until_separator(fhandoff, content, content_len)
	    || read_hmac_line(fhandoff, hmac_b64, hmac_b64_len)) {
		printf("errror");
		return 1;
	}

	return 0;
}

/*
 * Calculate the HMAC(SHA-256) from the content extracted
 * with the key K embedded:
 * Return: 0 success <-> 1 error
 */
int calculate_hmac(const unsigned char *content, int content_len,
		   unsigned char *hmac_calc, unsigned int *hmac_calc_len)
{

	if (!HMAC(EVP_sha256(), K, K_len, content, content_len, hmac_calc,
		  hmac_calc_len)) {
		warnx("HMAC calculation failed\n");
		return 1;
	}

	return 0;
}


/*
 * Encode to Base64 the HMAC calculated (ASCII):
 * Return: 0 success <-> 1 error
 */
int encode_base64(unsigned char *hmac_calc, unsigned int hmac_calc_len,
		  	unsigned char **hmac_b64_calc, int *hmac_b64_calc_len)
{
	*hmac_b64_calc_len = EVP_ENCODE_LENGTH(hmac_calc_len);
	*hmac_b64_calc = (unsigned char *)malloc(*hmac_b64_calc_len + 1);

	if (!hmac_b64_calc) {
		warnx("malloc failed for HMAC encoded in base 64\n");
		return 1;
	}

	*hmac_b64_calc_len =
	    EVP_EncodeBlock(*hmac_b64_calc, hmac_calc, hmac_calc_len);
	if (*hmac_b64_calc_len <= 0) {
		warnx("EVP_EncodeBlock failed or returned zero length");
		return 1;
	}

	return 0;
}

/*
 * Calculate HMAC(SHA-256) with key K embedded and encode to Base64:
 * Return: 0 success <-> 1 error
 */
int calc_and_encode_hmac(const char *content, int content_len,
			unsigned char **hmac_b64_calc, int *hmac_b64_calc_len)
{
	unsigned char hmac_calc[EVP_MAX_MD_SIZE];
	unsigned int hmac_calc_len = 0;

	if (calculate_hmac((const unsigned char *)content, content_len,
			   hmac_calc, &hmac_calc_len)) {
		return 1;
	}

	if (encode_base64(hmac_calc, hmac_calc_len, hmac_b64_calc,
			  	hmac_b64_calc_len)) {
		return 1;
	}

	return 0;
}

/*
 * Check if HMAC extracted and calculated are equal
 * Return: 0 success <-> 1 error
 */
int verify_hmac(const char *hmac_b64, int hmac_b64_len,
			unsigned char *hmac_b64_calc, int hmac_b64_calc_len)
{

	if (CRYPTO_memcmp(hmac_b64_calc, hmac_b64, hmac_b64_calc_len)) {
		warnx("\nHMAC verification failed: Invalid HMAC\n");
		return 1;
	}

	printf("\nHMAC verification successful: Valid HMAC\n");
	return 0;
}

/*
 * Check HMAC(SHA-256) calculated from the kernel is veridical:
 * Exit status: 0 success <-> 1 error
 */
int main(int argc, char *argv[])
{

	if (argc != 2) {
		errx(EXIT_FAILURE, "Usage: %s <path_file_handoff>\n"
		     "e.g.: %s ./file_handoff", argv[0], argv[0]);
	}

	const char *path_fhandoff = argv[1];

	// 1) Open a stream -> read line by line:
	FILE *fhandoff = fopen(path_fhandoff, "r");
	if (!fhandoff) {
		warnx("fopen failed\n");
		goto err_fhandoff;
	}

	// 2) Extract the content from the file:
	char *content = NULL;
	int content_len = 0;

	char *hmac_b64 = NULL;
	int hmac_b64_len = 0;

	if (extract_data(fhandoff, &content, &content_len,
			 &hmac_b64, &hmac_b64_len)) {
		goto free_cont;
	}
	fclose(fhandoff);
	fhandoff = NULL;

	printf("Extracted kernel content:\n%s\n", content);
	printf("Extracted HMAC(Base64):\n%s\n", hmac_b64);

	// 3) Calculate HMAC(SHA-256) of the content and encode it to Base64:
	unsigned char *hmac_b64_calc = NULL;
	int hmac_b64_calc_len = 0;

	if (calc_and_encode_hmac(content, content_len,
				 &hmac_b64_calc, &hmac_b64_calc_len)) {
		goto free_all;
	}

	free(content);
	content = NULL;

	printf("Calculated HMAC(Base64): \n%s\n", hmac_b64_calc);

	// 4) Compare HMAC(Base64) extracted from the file 
	// with the HMAC(Base64) calculated:
	int ext = verify_hmac(hmac_b64, hmac_b64_len, hmac_b64_calc,
			      	hmac_b64_calc_len);

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
