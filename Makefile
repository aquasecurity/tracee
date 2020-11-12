.PHONY: all
all: build

# environment:
ARCH ?= $(shell uname -m)
KERN_RELEASE ?= $(shell uname -r)
KERN_SRC ?= /lib/modules/$(KERN_RELEASE)/build
# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go' ! -name '*_test.go')
OUT_BIN := $(OUT_DIR)/tracee
BPF_SRC := tracee/tracee.bpf.c 
BPF_OBJ := $(OUT_DIR)/tracee.bpf.o
BPF_HEADERS := 3rdparty/include
BPF_BUNDLE := $(BPF_BUNDLE_DIR).tar.gz
LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/libbpf.a
OUT_DOCKER ?= tracee
RELEASE_ARCHIVE := $(OUT_DIR)/tracee.tar.gz
RELEASE_CHECKSUMS := $(OUT_DIR)/checksums.txt
RELEASE_DOCKER ?= aquasec/tracee
RELEASE_DOCKER_TAG ?= $(RELEASE_TAG:v%=%)
# tools:
LLC ?= llc
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
DOCKER ?= docker
GIT ?= git
CHECKSUM_TOOL ?= sha256sum
GITHUB_CLI ?= gh

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BIN)

$(OUT_BIN): $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(GO_SRC) $(BPF_BUNDLE) | $(OUT_DIR)
	GOOS=linux GOARCH=$(ARCH:x86_64=amd64) \
		CGO_CFLAGS="-I $(abspath $(LIBBPF_HEADERS))/bpf" \
		CGO_LDFLAGS="$(abspath $(LIBBPF_OBJ))" \
		go build -v -o $(OUT_BIN) \
		-ldflags "-X main.bpfBundleInjected=$$(base64 -w 0 $(BPF_BUNDLE))"

.PHONY: build-docker
build-docker: | $(OUT_DIR)
	img=$$($(DOCKER) build --target builder -q .) && \
	cnt=$$($(DOCKER) create $$img) && \
	$(DOCKER) cp $$cnt:/tracee/$(OUT_BIN) $(OUT_BIN) ; \
	$(DOCKER) rm $$cnt ; $(DOCKER) rmi $$img

bpf_compile_tools = $(LLC) $(CLANG)
.PHONY: $(bpf_compile_tools) 
$(bpf_compile_tools): % : check_%

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || ( echo "missing libbpf source, try git submodule update --init" ; false )

$(LIBBPF_HEADERS): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC)
	cd $(LIBBPF_SRC) && $(MAKE) install_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf 

$(LIBBPF_OBJ): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC) 
	cd $(LIBBPF_SRC) && $(MAKE) OBJDIR=$(abspath $(OUT_DIR))/libbpf BUILD_STATIC_ONLY=1 

bpf_bundle_dir := $(OUT_DIR)/tracee.bpf
$(BPF_BUNDLE): $(BPF_SRC) $(LIBBPF_HEADERS) $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)
	tar -czf $@ $(bpf_bundle_dir)

.PHONY: bpf
bpf: $(BPF_OBJ)
linux_arch := $(ARCH:x86_64=x86)
$(BPF_OBJ): $(BPF_SRC) $(LIBBPF_HEADERS) | $(OUT_DIR) $(bpf_compile_tools)
	$(CLANG) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(linux_arch) \
		-I $(LIBBPF_HEADERS)/bpf \
		-include $(KERN_SRC)/include/linux/kconfig.h \
		-I $(KERN_SRC)/arch/$(linux_arch)/include \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/uapi \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated \
		-I $(KERN_SRC)/arch/$(linux_arch)/include/generated/uapi \
		-I $(KERN_SRC)/include \
		-I $(KERN_SRC)/include/uapi \
		-I $(KERN_SRC)/include/generated \
		-I $(KERN_SRC)/include/generated/uapi \
		-I $(BPF_HEADERS) \
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
		-xc \
		-nostdinc \
		-O2 -emit-llvm -c -g $< -o $(@:.o=.ll)
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	-$(LLVM_STRIP) -g $@
	rm $(@:.o=.ll) 

# .PHONY: test
# test:
# 	go test -v ./...

.PHONY: clean
clean:
	-rm -rf dist $(OUT_DIR)
	-cd $(LIBBPF_SRC) && $(MAKE) clean;
	
check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

.PHONY: docker
docker:
	$(DOCKER) build -t $(OUT_DOCKER) .

$(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) &: $(OUT_BIN) LICENSE | $(OUT_DIR) check_$(CHECKSUM_TOOL)
	tar -czf $(RELEASE_ARCHIVE) $(OUT_BIN) LICENSE
	$(CHECKSUM_TOOL) $(RELEASE_ARCHIVE) > $(RELEASE_CHECKSUMS)

release_notes:=$(OUT_DIR)/release-notes.txt
.PHONY: release
# before running this rule, need to authenticate git, gh, and docker tools.
release: | check_$(GITHUB_CLI) $(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) #docker
	test -n '$(RELEASE_TAG)' || (echo "missing required variable RELEASE_TAG" ; false)
	rm $(release_notes)
	echo '## Changelog' > $(release_notes)
	$(GIT) log --pretty=oneline --abbrev=commit --no-decorate --no-color tags/$(shell $(GIT) describe --tags --abbrev=0)..HEAD >> $(release_notes)
	echo '' >> $(release_notes)
	echo '## Docker images' >> $(release_notes) >> $(release_notes)
	echo '- `docker pull docker.io/$(RELEASE_DOCKER):$(RELEASE_DOCKER_TAG)`' >> $(release_notes)
	echo '- `docker pull docker.io/$(RELEASE_DOCKER):latest`' >> $(release_notes)
	echo '' >>$(release_notes)
	$(GIT) tag $(RELEASE_TAG)
	$(GIT) push origin $(RELEASE_TAG)
	$(GITHUB_CLI) release create $(RELEASE_TAG) $(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) --title $(RELEASE_TAG) --notes-file $(release_notes)
	$(DOCKER) tag $(OUT_DOCKER) $(RELEASE_DOCKER):latest
	$(DOCKER) push $(RELEASE_DOCKER):latest
	$(DOCKER) tag $(OUT_DOCKER) $(RELEASE_DOCKER):$(RELEASE_DOCKER_TAG)
	$(DOCKER) push $(RELEASE_DOCKER):$(RELEASE_DOCKER_TAG)
