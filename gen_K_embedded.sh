#!/usr/bin/env zsh
set -e               # Salir si cualquier comando devuelve error (exit != 0)

# 1) Generar 64 bytes aleatorios y guardarlos en key.bin (binario) -> Clave óptima para SHA-256
KEY_LEN=64
openssl rand -out key.bin KEY_LEN

# 2) Convertir el binario a cabecera C con el símbolo K en un .h 
# --> Array de chars/bytes(const unsigned char K[]) y longitud (const unsigned int K_len=32)
xxd -i -n K key.bin | \
  sed -e 's/^unsigned char/const unsigned char/' \
      -e 's/^unsigned int/const unsigned int/' > K_embedded.h
echo "OK: generated K_embedded.h with key K (${KEY_LEN} bytes)."

# 3) Ejecutar este script y darle permisos de ejecución para ejecutarlo (externamente del script):
# chmod +x gen_K_embedded.sh
# ./gen_K_embedded.sh