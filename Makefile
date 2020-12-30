.PHONY: all
all: build bpf

# tools:
CMD_LLC ?= llc
CMD_CLANG ?= clang
CMD_LLVM_STRIP ?= llvm-strip
CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_CHECKSUM ?= sha256sum
CMD_GITHUB ?= gh
# environment:
ARCH_UNAME := $(shell uname -m)
ARCH ?= $(ARCH_UNAME:aarch64=arm64)
KERN_RELEASE ?= $(shell uname -r)
KERN_BLD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BLD_PATH)))
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags))
# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go')
OUT_BIN := $(OUT_DIR)/tracee
BPF_SRC := tracee/tracee.bpf.c 
OUT_BPF := $(OUT_DIR)/tracee.bpf.$(subst .,_,$(KERN_RELEASE)).$(subst .,_,$(VERSION)).o
BPF_HEADERS := 3rdparty/include
BPF_BUNDLE := $(OUT_DIR)/tracee.bpf.tar.gz
LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/libbpf.a
OUT_DOCKER ?= tracee
DOCKER_BUILDER ?= tracee-builder
# DOCKER_BUILDER_KERN_SRC(/BLD) is where the docker builder looks for kernel headers
DOCKER_BUILDER_KERN_BLD ?= $(if $(shell readlink $(KERN_BLD_PATH)),$(shell readlink $(KERN_BLD_PATH)),$(KERN_BLD_PATH))
DOCKER_BUILDER_KERN_SRC ?= $(if $(shell readlink $(KERN_SRC_PATH)),$(shell readlink $(KERN_SRC_PATH)),$(KERN_SRC_PATH))
# DOCKER_BUILDER_KERN_SRC_MNT is the kernel headers directory to mount into the docker builder container. DOCKER_BUILDER_KERN_SRC should usually be a decendent of this path.
DOCKER_BUILDER_KERN_SRC_MNT ?= $(dir $(DOCKER_BUILDER_KERN_SRC))
RELEASE_ARCHIVE := $(OUT_DIR)/tracee.tar.gz
RELEASE_CHECKSUMS := $(OUT_DIR)/checksums.txt
RELEASE_DOCKER ?= aquasec/tracee
RELEASE_DOCKER_TAG ?= $(RELEASE_TAG:v%=%)

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BIN)

go_env := GOOS=linux GOARCH=$(ARCH:x86_64=amd64) CC=$(CMD_CLANG) CGO_CFLAGS="-I $(abspath $(LIBBPF_HEADERS))" CGO_LDFLAGS="$(abspath $(LIBBPF_OBJ))"
ifndef DOCKER
$(OUT_BIN): $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(filter-out *_test.go,$(GO_SRC)) $(BPF_BUNDLE) | $(OUT_DIR)
	$(go_env) go build -v -o $(OUT_BIN) \
	-ldflags "-X main.bpfBundleInjected=$$(base64 -w 0 $(BPF_BUNDLE)) -X main.version=$(VERSION)"	
else 
$(OUT_BIN): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$($@))
endif

bpf_compile_tools = $(CMD_LLC) $(CMD_CLANG)
.PHONY: $(bpf_compile_tools) 
$(bpf_compile_tools): % : check_%

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || git submodule update --init || (echo "missing libbpf source" ; false)

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC)
	cd $(LIBBPF_SRC) && $(MAKE) install_headers install_uapi_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf

$(LIBBPF_OBJ): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC) 
	cd $(LIBBPF_SRC) && $(MAKE) OBJDIR=$(abspath $(OUT_DIR))/libbpf BUILD_STATIC_ONLY=1 

bpf_bundle_dir := $(OUT_DIR)/tracee.bpf
$(BPF_BUNDLE): $(BPF_SRC) $(LIBBPF_HEADERS)/bpf $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)
	tar -czf $@ $(bpf_bundle_dir)

.PHONY: bpf
bpf: $(OUT_BPF)

linux_arch := $(ARCH:x86_64=x86)
ifndef DOCKER
$(OUT_BPF): $(BPF_SRC) $(LIBBPF_HEADERS) | $(OUT_DIR) $(bpf_compile_tools)
	@v=$$($(CMD_CLANG) --version); test $$(echo $${v#*version} | head -n1 | cut -d '.' -f1) -ge '9' || (echo 'required minimum clang version: 9' ; false)
	$(CMD_CLANG) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(linux_arch) \
		-I $(LIBBPF_HEADERS)/bpf \
		-include $(KERN_SRC_PATH)/include/linux/kconfig.h \
		-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include \
		-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include/uapi \
		-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated \
		-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated/uapi \
		-I $(KERN_SRC_PATH)/include \
		-I $(KERN_BLD_PATH)/include \
		-I $(KERN_SRC_PATH)/include/uapi \
		-I $(KERN_BLD_PATH)/include/generated \
		-I $(KERN_BLD_PATH)/include/generated/uapi \
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
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	-$(CMD_LLVM_STRIP) -g $@
	rm $(@:.o=.ll)
else
$(OUT_BPF): $(DOCKER_BUILDER) | $(OUT_DIR) 
	$(call docker_builder_make,$($@))
endif


.PHONY: test 
ifndef DOCKER
test: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ)
	$(go_env)	go test -v ./...
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,test)
endif

.PHONY: $(DOCKER_BUILDER)
# record built image id to prevent unnecessary building and for cleanup
$(DOCKER_BUILDER): $(OUT_DIR)/$(DOCKER_BUILDER)

$(OUT_DIR)/$(DOCKER_BUILDER): $(GO_SRC) $(BPF_SRC) $(MAKEFILE_LIST) Dockerfile | $(OUT_DIR)
	$(CMD_DOCKER) build -f Dockerfile.builder -t $(DOCKER_BUILDER) --iidfile $(OUT_DIR)/$(DOCKER_BUILDER) --target builder .

# docker_builder_make runs a make command in the tracee-builder container
define docker_builder_make
	$(CMD_DOCKER) run --rm \
	-v $(abspath $(DOCKER_BUILDER_KERN_SRC_MNT)):$(DOCKER_BUILDER_KERN_SRC_MNT) \
	-v $(abspath .):/tracee \
	--entrypoint make $(DOCKER_BUILDER) KERN_BLD_PATH=$(DOCKER_BUILDER_KERN_BLD) KERN_SRC_PATH=$(DOCKER_BUILDER_KERN_SRC) $(1)
endef

.PHONY: clean
clean:
	-$(CMD_DOCKER) rmi $(file < $(DOCKER_BUILDER))
	-rm -rf dist $(OUT_DIR)
	-cd $(LIBBPF_SRC) && $(MAKE) clean;
	
check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

.PHONY: docker
docker:
	$(CMD_DOCKER) build --build-arg VERSION=$(VERSION) -t $(OUT_DOCKER):latest .

.PHONY: docker-slim
docker-slim:
	$(CMD_DOCKER) build --build-arg VERSION=$(VERSION) -t $(OUT_DOCKER):slim --build-arg BASE=slim .

# release_docker_image accepts a local docker image reference (first argument), pushes it under a new name  (second argument) to remote repository, and records it in the release notes
define release_docker_image
	$(CMD_DOCKER) tag $(1) $(2) && $(CMD_DOCKER) push $(2) &&	echo '- `docker pull docker.io/$(2)`' >> $(release_notes);
endef

$(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) &: $(OUT_BIN) LICENSE | $(OUT_DIR) check_$(CMD_CHECKSUM)
	tar -czf $(RELEASE_ARCHIVE) $(OUT_BIN) LICENSE
	$(CMD_CHECKSUM) $(RELEASE_ARCHIVE) > $(RELEASE_CHECKSUMS)

release_notes := $(OUT_DIR)/release-notes.txt
release_images_fat := $(RELEASE_DOCKER):latest $(RELEASE_DOCKER):$(RELEASE_DOCKER_TAG)
release_images_slim := $(RELEASE_DOCKER):slim $(RELEASE_DOCKER):slim-$(RELEASE_DOCKER_TAG)
.PHONY: release
# before running this rule, need to authenticate git, gh, and docker tools.
release: | check_$(CMD_GITHUB) $(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) docker docker-slim
	test -n '$(RELEASE_TAG)' || (echo "missing required variable RELEASE_TAG" ; false)
	-rm $(release_notes)
	echo '## Changelog' > $(release_notes)
	$(CMD_GIT) log --pretty=oneline --abbrev=commit --no-decorate --no-color tags/$(shell $(CMD_GIT) describe --tags --abbrev=0)..HEAD >> $(release_notes)
	echo '' >> $(release_notes)
	echo '## Docker images' >> $(release_notes)
	$(foreach img,$(release_images_fat),$(call release_docker_image,$(OUT_DOCKER):latest,$(img)))
	$(foreach img,$(release_images_slim),$(call release_docker_image,$(OUT_DOCKER):slim,$(img)))
	echo '' >>$(release_notes)
	$(CMD_GIT) tag $(RELEASE_TAG)
	$(CMD_GIT) push origin $(RELEASE_TAG)
	$(CMD_GITHUB) release create $(RELEASE_TAG) $(RELEASE_ARCHIVE) $(RELEASE_CHECKSUMS) --title $(RELEASE_TAG) --notes-file $(release_notes)
