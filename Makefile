# Globa Usage: make MODULE=name_without_extension
# e.g.: make MODULE=hw

ifneq ($(MODULE),)
obj-m := $(MODULE).o		# obj-m = hw.o --> static usage
else
$(error You might indicate the module name: make MODULE=<name_without_extension>)
endif

all:
		make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD)	modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD)	clean
