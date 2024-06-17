obj-m += hooker.o

PWD := $(shell pwd)

KBUILD_CFLAGS += -g -Wall
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

hooker.o:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -f hooker.mod hooker.o hooker.mod.c hooker.mod.o hooker.ko
	rm -f modules.order Module.symvers
