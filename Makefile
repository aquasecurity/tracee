OUTPUT := .output
TARGET := event_monitor_ebpf
KERN_RELEASE := $(shell uname -r)
KERN_SRC := /lib/modules/$(KERN_RELEASE)/build
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LLC ?= llc
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_C = tracee/${TARGET:=.c}
BPF_OBJ = ${OUTPUT}/${TARGET:=.o}
LIBBPF_SRC = $(abspath 3rdparty/libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
CFLAGS ?= -I$(OUTPUT)/usr/include/

SRC = $(shell find . -type f -name '*.go' ! -name '*_test.go' )
ebpfProgramBase64 = $(shell base64 -w 0 tracee/event_monitor_ebpf.c)

.PHONY: build
build: llvm-check $(BPF_OBJ) dist/tracee

.PHONY: build-docker
build-docker: clean
	img=$$(docker build --target builder -q  .) && \
	cnt=$$(docker create $$img) && \
	docker cp $$cnt:/tracee/dist - | tar -xf - ; \
	docker rm $$cnt ; docker rmi $$img

dist/tracee: $(SRC) tracee/event_monitor_ebpf.c
	GOOS=linux go build -v -o dist/tracee -ldflags "-X github.com/aquasecurity/tracee/tracee.ebpfProgramBase64Injected=$(ebpfProgramBase64)"

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf dist || true
	cd $(LIBBPF_SRC) && $(MAKE) clean;
	rm -f $(BPF_OBJ)
	rm -f *.ll
	rm -rf .output

imageName ?= tracee
.PHONY: docker
docker:
	docker build -t $(imageName) .

.PHONY: release
# release by default will not publish. run with `publish=1` to publish
goreleaserFlags = --skip-publish --snapshot
ifdef publish
	goreleaserFlags =
endif
release:
	EBPFPROGRAM_BASE64=$(ebpfProgramBase64) goreleaser release --rm-dist $(goreleaserFlags)

.PHONY: $(CLANG) $(LLC)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OUTPUT):
	mkdir -p $@

$(LIBBPF_OBJ):
	@if [ ! -d $(LIBBPF_SRC) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_SRC) && $(MAKE) BUILD_STATIC_ONLY=1; \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) $(MAKE) install_headers; \
	fi

$(BPF_OBJ): ${BPF_C} $(LIBBPF_OBJ) | ${OUTPUT}
	$(CLANG) -S \
		-D __BPF_TRACING__ -D __KERNEL__ -D__TARGET_ARCH_$(ARCH) \
		$(CFLAGS) \
		-include $(KERN_SRC)/include/linux/kconfig.h \
		-I $(KERN_SRC)/arch/$(ARCH)/include \
		-I $(KERN_SRC)/arch/$(ARCH)/include/uapi \
		-I $(KERN_SRC)/arch/$(ARCH)/include/generated \
		-I $(KERN_SRC)/arch/$(ARCH)/include/generated/uapi \
		-I $(KERN_SRC)/include \
		-I $(KERN_SRC)/include/uapi \
		-I $(KERN_SRC)/include/generated \
		-I $(KERN_SRC)/include/generated/uapi \
		-I 3rdparty/include \
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
