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

#define KEY_SIZE 32     // Longitud en bytes que queremos que tome la clave simétrica => K

// Imprimir array de bytes en hexadecimal
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // 0x%02x lo muestra en hex con 2 dígitos, rellenando con ceros si hace falta (por ejemplo 0x0a)
        // segundo %s imprime coma y espacio ", " salvo en el último elemento (donde imprime cadena vacía "")
        printf("0x%02x%s", data[i], (i == len-1) ? "" : ", ");
    }
}

// Asegurarnos que se realiza la lectura completa: (return -1 en error)
static int read_full(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, (unsigned char*)buf + off, len - off);
        if (r < 0) {
            if (errno == EINTR) {   // reintentar si fue interrumpido
                continue;
            }
            return -1;
        }
        if (r == 0) {   // EOF inesperado
            break;
        }
        off += (size_t)r;   // Sumar el offset ya leído
    }
    return (off == len) ? 0 : -1;   // Devolver 0 si se ha leído lo pedido o -1 en otro caso
}

// Asegurarnos que hace la lectura completa:    (return -1 en error)
static int write_full(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const unsigned char*)buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {   // reintentar si fue interrumpido
                continue;
            }
            return -1;
        }
        off += (size_t)w;   // Sumar el offset ya escrito
    }
    return 0;       // Devolver 0 en caso de haber escrito lo pedido
}



int main(void) {
    // Array de chars(bytes) inicializados
    unsigned char key[32];

    // 1) 32 bytes aleatorios desde /dev/urandom
    // Abrir fichero de binarios aleatorios
    int fdrand = open("/dev/urandom", O_RDONLY);
    // Error al acceder al fichero:
    if (fdrand < 0) {
        err(EXIT_FAILURE, "Error opening /dev/urandom"); 
    }
    // Leer de fichero binario (fdrand es fd de "/dev/urandom") 32 bytes(KEY_SIZE) 
    // (bytes reservados para el array de chars) y guardarlo en el array key
    if (read_full(fdrand, key, KEY_SIZE) != 0) {
        close(fdrand);
        err(EXIT_FAILURE, "Error reading /dev/urandom"); 
    }
    if (close(fdrand) < 0) {
        err(EXIT_FAILURE, "Error closing key.bin");
    }

    // 2) Guardar binario en un fichero .bin (creado)
    // Crear/sobreescribir fichero binario "key.bin" con solo permisos para el dueño --> fd
    int fd = open("key.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        err(EXIT_FAILURE, "Error opening key.bin");
    }
    // Escribir en el fichero binario (fd --> key.bin) el array de bytes(chars) key cuya longitud son 32 bytes (KEY_SIZE)
    if (write_full(fd, key, KEY_SIZE) != 0) {
        close(fd);
        err(EXIT_FAILURE, "Error writing key.bin"); 
    }
    if (close(fd) < 0) {
        err(EXIT_FAILURE, "Error closing key.bin");
    }

    // 3) Mostrar el array en C directamente
    printf("/* Array en C (en memoria ahora mismo) */\n");
    printf("unsigned char key[32] = {");
    print_hex(key, KEY_SIZE);
    printf("};\n\n");
    // Usar xxd/od para convertir el binario a array de chars en C
    // xxd -i genera un array listo para copiar/pegar --> También se puede usar od (no da array C, solo bytes):
    printf("/* xxd -i key.bin */\n");
    system("xxd -i key.bin");   // Ejecuta llamada al sistema xxd

    // 4) Crear/abrir fichero de prueba "file_test.txt" y escribir el contenido
    const char *test_path = "file_test.txt";
    const char *content = "Hi HMAC with SHA-256!\n";
    fd = open(test_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        err(EXIT_FAILURE, "Error opening(%s)", test_path);
    }
    if (write_full(fd, content, strlen(content)) != 0) { 
        close(fd);
        err(EXIT_FAILURE, "Error writing(%s)", test_path);
    }
    if (close(fd) < 0) {
        err(EXIT_FAILURE, "close(%s)", test_path);
    }

    // 5) OPENSSL --> Crear HASH de autenticación para certificado HMAC
    // con la clave 'key' mediante el algoritmo de clave simétrica SHA-256
    // Buffer para almacenar el resultado del HMAC
    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned int len = SHA256_DIGEST_LENGTH;
    // HMAC(algoritmo_hash, clave, longitud_clave, mensaje, longitud_mensaje, resultado, longitud_resultado)
    HMAC(
        EVP_sha256(),       // Algoritmo de hash --> SHA-256
        key,                // Clave secreta creada
        KEY_SIZE,        // Longitud de la clave
        (unsigned char *)content, // Mensaje --> como array de chars (bytes)
        strlen(content),    // Longitud del mensaje
        result,             // Buffer de salida
        &len                // Longitud del buffer de salida
    );
    // Imprimir el resultado del HMAC en formato hexadecimal
    printf("HMAC-SHA256 del mensaje:\n");
    printf("HMAC(SHA-256) = {");
    print_hex(result, len);
    printf("};\n\n");


    




    return EXIT_SUCCESS;
}
