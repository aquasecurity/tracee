TARGET := self
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := $(shell find . -type f -name '*.go')
LIBBPFGO_SRC := $(shell find ../.. -type f -name '*.go')
BPF_SRC := $(shell find . -type f -name '*.bpf.c')
PWD := $(shell pwd)

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib64/libbpf.a

.PHONY: all
all: vmlinux.h $(TARGET) $(TARGET_BPF)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

go_env := CC=gcc CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC) $(LIBBPFGO_SRC)
	$(go_env) go build -ldflags '-extldflags "-static"' -o $(TARGET) 

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-g -O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean: 
	rm $(TARGET) $(TARGET_BPF) vmlinux.h
