# Usage: make MODULE=name_without_extension
# e.g.: make MODULE=hw

ifneq ($(MODULE),)
obj-m := $(MODULE).o
else
$(error You might indicate the module name: make MODULE=<name_without_extension>)
endif

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean