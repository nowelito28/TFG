// Hacer prueba en espacio de user de clave simétrica
// Generarla para un HMAC(SHA 256)
// 1.Base64 (string) --> encodearla a cadena de bytes
// 2. binario aleatorio de 32 bytes con xxd --> cadena de hexadecimales

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define KEY_SIZE 32		// Longitud en bytes que queremos que tome la clave simétrica => K

// Imprimir array de bytes en hexadecimal
void
print_hex (const unsigned char *data, size_t len)
{
  for (size_t i = 0; i < len; ++i)
    {
      // 0x%02x lo muestra en hex con 2 dígitos, rellenando con ceros si hace falta (por ejemplo 0x0a)
      // segundo %s imprime coma y espacio ", " salvo en el último elemento (donde imprime cadena vacía "")
      printf ("0x%02x%s", data[i], (i == len - 1) ? "" : ", ");
    }
}

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
	{			// EOF inesperado
	  break;
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



int
main (void)
{
  // Array de chars(bytes) inicializados
  unsigned char key[32];

  // 1) 32 bytes aleatorios desde /dev/urandom
  // Abrir fichero de binarios aleatorios
  int fdrand = open ("/dev/urandom", O_RDONLY);
  // Error al acceder al fichero:
  if (fdrand < 0)
    {
      err (EXIT_FAILURE, "Error opening /dev/urandom");
    }
  // Leer de fichero binario (fdrand es fd de "/dev/urandom") 32 bytes(KEY_SIZE) 
  // (bytes reservados para el array de chars) y guardarlo en el array key
  if (read_full (fdrand, key, KEY_SIZE) != 0)
    {
      close (fdrand);
      err (EXIT_FAILURE, "Error reading /dev/urandom");
    }
  if (close (fdrand) < 0)
    {
      err (EXIT_FAILURE, "Error closing key.bin");
    }

  // 2) Guardar binario en un fichero .bin (creado)
  // Crear/sobreescribir fichero binario "key.bin" con solo permisos para el dueño --> fd
  int fd = open ("key.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    {
      err (EXIT_FAILURE, "Error opening key.bin");
    }
  // Escribir en el fichero binario (fd --> key.bin) el array de bytes(chars) key cuya longitud son 32 bytes (KEY_SIZE)
  if (write_full (fd, key, KEY_SIZE) != 0)
    {
      close (fd);
      err (EXIT_FAILURE, "Error writing key.bin");
    }
  if (close (fd) < 0)
    {
      err (EXIT_FAILURE, "Error closing key.bin");
    }

  // 3) Mostrar el array en C directamente
  printf ("/* Array en C (en memoria ahora mismo) */\n");
  printf ("unsigned char key[32] = {");
  print_hex (key, KEY_SIZE);
  printf ("};\n\n");
  // Usar xxd/od para convertir el binario a array de chars en C
  // xxd -i genera un array listo para copiar/pegar --> También se puede usar od (no da array C, solo bytes):
  printf ("/* xxd -i key.bin */\n");
  system ("xxd -i key.bin");	// Ejecuta llamada al sistema xxd

  // 4) OPENSSL --> Crear HASH de autenticación para certificado HMAC
  // con la clave 'key' mediante el algoritmo de clave simétrica SHA-256
  // Buffer para almacenar el resultado del HMAC
  unsigned char hmac_result[SHA256_DIGEST_LENGTH];
  unsigned int hmac_len = SHA256_DIGEST_LENGTH;
  // Contenido del mensaje a firmar --> para hacer el HASH
  const char *content = "Hi HMAC with SHA-256!\n";
  // HMAC(algoritmo_hash, clave, longitud_clave, mensaje, longitud_mensaje, resultado, longitud_resultado)
  HMAC (EVP_sha256 (),		// Algoritmo de hash --> SHA-256
	key,			// Clave secreta creada
	KEY_SIZE,		// Longitud de la clave
	(unsigned char *) content,	// Mensaje --> como array de chars (bytes)
	strlen (content),	// Longitud del mensaje
	hmac_result,		// Buffer de salida --> HMAC
	&hmac_len		// Longitud del buffer de salida --> Longitud del HMAC (se sobreescribe la variable)
    );
  if (!HMAC)
    {
      errx (EXIT_FAILURE, "HMAC(EVP_sha256) failed");
    }
  // Imprimir el resultado del HMAC en formato hexadecimal
  printf ("HMAC-SHA256 del mensaje:\n");
  printf ("HMAC(SHA-256) = {");
  print_hex (hmac_result, hmac_len);
  printf ("};\n\n");

  // 5) Juntar todo el contenido a guardar en el fichero de texto => contetn + separador + HMAC (Base64)
  static const char *sep = "\n\n---\n\n";	// Separador entre el contenido y el HMAC
  // Cadena de chars concatenando el contenido, el separador y el HMAC (base 64)
  // Codificar hmac_result a Base64:
  // Longitud del Base64: cada 3 bytes se codifican en 4 caracteres -> si no es múltiplo de 3 se añade padding '='
  size_t base64_len = 4 * ((hmac_len + 2) / 3);
  char *b64 = malloc (base64_len + 1);	/* +1 para '\0' */
  if (!b64)
    {
      err (EXIT_FAILURE, "Error in malloc base64");
    }
  // Codificar certificado HMAC (array de bytes) a Base64 --> Devuelve longitud del Base64 (no incluye el '\0')
  int b64_out =
    EVP_EncodeBlock ((unsigned char *) b64, hmac_result, (int) hmac_len);
  if (b64_out < 0)
    {
      free (b64);
      errx (EXIT_FAILURE, "EVP_EncodeBlock failed");
    }
  b64[b64_out] = '\0';		// Añadir el '/0' al final de la cadena Base64
  size_t total_len = strlen (content) + strlen (sep) + (size_t) b64_out + 1;	// +1 para '\0'
  // Crear cadena para el contenido completo concatenado
  char *full_content = malloc (total_len);
  if (!full_content)
    {
      free (b64);
      err (EXIT_FAILURE, "Error in malloc full_content");
    }
  full_content[0] = '\0';	// Inicializar a cadena vacía
  strcat (full_content, content);
  strcat (full_content, sep);
  strcat (full_content, b64);
  free (b64);			// Liberar memoria del Base64 --> Ya no se usa más
  b64 = NULL;

  // 6) Crear/abrir fichero de prueba "file_test.txt" y escribir el contenido con certificado HMAC(SHA-256)
  const char *test_path = "file_test.txt";
  fd = open (test_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    {
      free (full_content);
      err (EXIT_FAILURE, "Error opening(%s)", test_path);
    }
  if (write_full (fd, full_content, total_len) != 0)
    {
      close (fd);
      free (full_content);
      err (EXIT_FAILURE, "Error writing(%s)", test_path);
    }
  free (full_content);		// Liberar memoria del contenido completo --> Ya no se usa más
  full_content = NULL;
  if (close (fd) < 0)
    {
      err (EXIT_FAILURE, "Error closing(%s)", test_path);
    }



  return EXIT_SUCCESS;
}
