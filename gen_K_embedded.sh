#!/usr/bin/env zsh
set -e               # Salir si cualquier comando devuelve error (exit != 0)

# 1) Generar 32 bytes aleatorios y guardarlos en key.bin (binario)
openssl rand -out key.bin 32

# 2) Convertir el binario a cabecera C con el símbolo K en un .h --> Array de chars/bytes(unsigned char K[]) y longitud (unsigned int K_len=32)
xxd -i -n K key.bin > K_embedded.h
echo "OK: generated K_embedded.h with key K (32 bytes)."

# 3) Ejecutar este script y darle permisos de ejecución para ejecutarlo (externamente del script):
# chmod +x gen_K_embedded.sh
# ./gen_K_embedded.sh