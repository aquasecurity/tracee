.PHONY: all
all: build

OUT_DIR := .output

$(OUT_DIR):
	mkdir -p $@

ARCH := $(shell uname -m)
bpf_src := tracee/event_monitor_ebpf.c 
bpf_out := $(OUT_DIR)/event_monitor_ebpf.o
go_src := $(shell find . -type f -name '*.go' ! -name '*_test.go')
bin_out := $(OUT_DIR)/tracee

.PHONY: build
build: $(bin_out)

$(bin_out): $(bpf_out) $(go_src) | $(OUT_DIR)
	GOOS=linux GOARCH=$(ARCH:x86_64=amd64) go build -v -o $(bin_out)

# .PHONY: build-docker
# build-docker: clean
# 	img=$$(docker build --target builder -q  .) && \
# 	cnt=$$(docker create $$img) && \
# 	docker cp $$cnt:/tracee/dist - | tar -xf - ; \
# 	docker rm $$cnt ; docker rmi $$img

LLC ?= llc
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
bpf_compile_tools = $(LLC) $(CLANG) $(LLVM_STRIP)

.PHONY: $(bpf_compile_tools) 
$(bpf_compile_tools): % : check_%

libbpf_src := 3rdparty/libbpf/src
libbpf_out_headers_dir := $(OUT_DIR)/usr/include

$(libbpf_src):
	test -d $(libbpf_src) || ( echo "missing libbpf source, try git submodule update --init" ; false )

$(libbpf_out_headers_dir) : | $(OUT_DIR) $(bpf_compile_tools) $(libbpf_src)
	cd $(libbpf_src) && $(MAKE) BUILD_STATIC_ONLY=1 && \
	$(MAKE) install_headers DESTDIR=$(abspath $(OUT_DIR)) 

linux_arch := $(ARCH:x86_64=x86)
extra_headers_dirs := 3rdparty/include #copy to out?
KERN_RELEASE := $(shell uname -r)
KERN_SRC := /lib/modules/$(KERN_RELEASE)/build

$(bpf_out): $(bpf_src) $(libbpf_out_headers_dir) | $(OUT_DIR) $(bpf_compile_tools)
	$(CLANG) -S \
		-D __BPF_TRACING__ -D __KERNEL__ -D__TARGET_ARCH_$(linux_arch) \
		-I $(libbpf_out_headers_dir) \
		-include $(KERN_SRC)/include/linux/kconfig.h \
		-I $(KERN_SRC)/arch/$(linux_arch)/include \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/uapi \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated/uapi \
		-I $(KERN_SRC)/include \
		-I $(KERN_SRC)/include/uapi \
		-I $(KERN_SRC)/include/generated \
		-I $(KERN_SRC)/include/generated/uapi \
		-I $(extra_headers_dirs) \
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
	-cd $(libbpf_src) && $(MAKE) clean;
	
check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

# DOCKER_OUT ?= tracee
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
