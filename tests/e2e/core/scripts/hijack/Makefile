obj-m += hijack.o

PWD := $(shell pwd)

KBUILD_CFLAGS += -g -Wall
# emit endbr64 in function prologues so the module loads on an IBT-enforcing
# kernel (CONFIG_X86_KERNEL_IBT); the kernel tree normally injects this, this is
# insurance for a tree that does not. x86_64-only, like these tests.
ccflags-y += -fcf-protection=branch
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# target must NOT be named hijack.o: that shadows kbuild's own rule for the
# object and, on a clean tree, makes kbuild run this recursive recipe while
# building the module - which trips the kernel Makefile into writing into its
# (read-only) source tree. 'all' is a plain wrapper and leaves kbuild's rules
# intact for the out-of-tree (M=) build path used by the microVM prebuild.
all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -f hijack.mod hijack.o hijack.mod.c hijack.mod.o hijack.ko
	rm -f modules.order Module.symvers
	rm -f .*.cmd
