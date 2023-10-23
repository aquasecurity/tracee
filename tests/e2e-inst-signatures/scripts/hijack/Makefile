obj-m += hijack.o

PWD := $(shell pwd)

KBUILD_CFLAGS += -g -Wall
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

hijack.o:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -f hijack.mod hijack.o hijack.mod.c hijack.mod.o hijack.ko
	rm -f modules.order Module.symvers
