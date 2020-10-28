.PHONY: all
all: build

# environment:
ARCH := $(shell uname -m)
KERN_RELEASE := $(shell uname -r)
KERN_SRC := /lib/modules/$(KERN_RELEASE)/build
# inputs and outputs:
OUT_DIR := dist
BPF_SRC := tracee/tracee.bpf.c 
BPF_OBJ := $(OUT_DIR)/tracee.bpf.o
GO_SRC := $(shell find . -type f -name '*.go' ! -name '*_test.go')
OUT_BIN := $(OUT_DIR)/tracee
LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/libbpf.a
OUT_DOCKER := tracee
# tools:
LLC := llc
CLANG := clang
LLVM_STRIP := llvm-strip
# DOCKER := docker
# GORELEASER := goreleaser

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BIN) $(BPF_OBJ)

$(OUT_BIN): $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(GO_SRC) | $(OUT_DIR)
	GOOS=linux GOARCH=$(ARCH:x86_64=amd64) \
		CGO_CFLAGS="-I $(abspath $(LIBBPF_HEADERS))/bpf" \
		CGO_LDFLAGS="$(abspath $(LIBBPF_OBJ))" \
		go build -v -o $(OUT_BIN) \
		-ldflags "-X github.com/aquasecurity/tracee/tracee.ebpfProgramB64Injected=$$(base64 -w 0 $(BPF_SRC))"

# .PHONY: build-docker
# build-docker: clean
# 	img=$$(docker build --target builder -q  .) && \
# 	cnt=$$(docker create $$img) && \
# 	docker cp $$cnt:/tracee/dist - | tar -xf - ; \
# 	docker rm $$cnt ; docker rmi $$img

bpf_compile_tools = $(LLC) $(CLANG) $(LLVM_STRIP)
.PHONY: $(bpf_compile_tools) 
$(bpf_compile_tools): % : check_%

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || ( echo "missing libbpf source, try git submodule update --init" ; false )

$(LIBBPF_HEADERS): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC)
	cd $(LIBBPF_SRC) && $(MAKE) install_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf 

$(LIBBPF_OBJ): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC) 
	cd $(LIBBPF_SRC) && $(MAKE) OBJDIR=$(abspath $(OUT_DIR))/libbpf BUILD_STATIC_ONLY=1 

linux_arch := $(ARCH:x86_64=x86)
bpf_extra_headers := 3rdparty/include #copy to out?
$(BPF_OBJ): $(BPF_SRC) $(LIBBPF_HEADERS) | $(OUT_DIR) $(bpf_compile_tools)
	$(CLANG) -S \
		-D __BPF_TRACING__ -D __KERNEL__ -D__TARGET_ARCH_$(linux_arch) \
		-I $(LIBBPF_HEADERS) \
		-include $(KERN_SRC)/include/linux/kconfig.h \
		-I $(KERN_SRC)/arch/$(linux_arch)/include \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/uapi \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated/uapi \
		-I $(KERN_SRC)/include \
		-I $(KERN_SRC)/include/uapi \
		-I $(KERN_SRC)/include/generated \
		-I $(KERN_SRC)/include/generated/uapi \
		-I $(bpf_extra_headers) \
		-Wno-address-of-packed-member \
		-Wno-compare-distinct-pointer-types \
		-Wno-deprecated-declarations \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-pointer-sign \
		-Wno-pragma-once-outside-heade \
		-Wno-unknown-warning-option \
		-Wno-unused-value \
		-Wunused \
		-Wall \
		-fno-stack-protector \
		-fno-jump-tables \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-x c \
		-nostdinc \
		-O2 -emit-llvm -c -g $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	$(LLVM_STRIP) -g $@

# .PHONY: test
# test:
# 	go test -v ./...

.PHONY: clean
clean:
	-rm -rf dist $(OUT_DIR)
	-cd $(LIBBPF_SRC) && $(MAKE) clean;
	
check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

# .PHONY: docker
# docker:
# 	docker build -t $(DOCKER_OUT) .

# ifdef PUBLISH
# 	goreleaser_publish_flags =
# endif
# goreleaser_publish_flags = --skip-publish --snapshot
# # release by default will not publish. run with `PUBLISH=1` to publish
# .PHONY: release
# release:
# 	goreleaser release --rm-dist $(goreleaser_publish_flags)
