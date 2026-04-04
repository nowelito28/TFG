#!/usr/bin/env zsh
set -e               # Exit if any command returns error (exit != 0)

# 1) Generate 64 random bytes and save it in key.bin (binary file) -> Optimal for key SHA-256
KEY_LEN=64
openssl rand -out key.bin ${KEY_LEN}

# 2) Convert the binary to a C header with symbol K in a .h 
# --> Chars/bytes array(const unsigned char K[]) and length (const unsigned int K_len=64)
xxd -i -n K key.bin | \
  sed -e 's/^unsigned char/const unsigned char/' \
      -e 's/^unsigned int/const unsigned int/' > k_embedded.h
echo "OK: generated k_embedded.h with key K (${KEY_LEN} bytes)."

# 3) Get this script executed and give it execution permissions (externally from script):
# chmod +x gen_k_embedded.sh
# ./gen_k_embedded.sh