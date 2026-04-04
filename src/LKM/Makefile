SEALFS_VERSION="0.91"

# Adds an extra flag/option to the compiler (gcc) when compiling .c modules with kbuild":
# EXTRA_CFLAGS += -DSEALFS_VERSION=\"$(SEALFS_VERSION)\"
EXTRA_CFLAGS += -DSEALFS_VERSION=\"0.91\" 

# Name of the main .c module to be compiled with kbuild --> .ko:
obj-m += crypto_fd.o

# Tell the compiler (gcc) if the module is composed of multiple object files (NOT just the main one)
# sealfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

# 1. Switch to the build directory of the current kernel -> make -C /lib/modules/$(shell uname -r)/build
# 2. Tell the kernel build system to compile the local Makefile in the current directory (pwd) -> M=$(shell pwd)
# 3. Specify to compile external modules -> modules
all: k_embedded.h
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

# Clean all intermediate files created (*.o, *.mod.c, *.symvers, etc.) -> clean directory
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

# Indicates that all and clean are not files, but “phony” targets -> To avoid confusion with files of the same name
.PHONY: all clean