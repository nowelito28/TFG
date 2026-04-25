savedcmd_crypto_fd.mod := printf '%s\n'   crypto_fd.o | awk '!x[$$0]++ { print("./"$$0) }' > crypto_fd.mod
