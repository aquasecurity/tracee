.PHONY: all | env
all: tracee-ebpf tracee-rules signatures tracee

#
# make
#

.ONESHELL:
SHELL = /bin/sh

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
MAKE = make
MAKEFLAGS += --no-print-directory

#
# tools
#

CMD_AWK ?= awk
CMD_CAT ?= cat
CMD_CLANG ?= clang
CMD_CUT ?= cut
CMD_ERRCHECK ?= errcheck
CMD_GIT ?= git
CMD_GO ?= go
CMD_GREP ?= grep
CMD_INSTALL ?= install
CMD_LLC ?= llc
CMD_MD5 ?= md5sum
CMD_MKDIR ?= mkdir
CMD_OPA ?= opa
CMD_PKGCONFIG ?= pkg-config
CMD_RM ?= rm
CMD_SED ?= sed
CMD_STATICCHECK ?= staticcheck
CMD_STRIP ?= llvm-strip
CMD_TOUCH ?= touch
CMD_TR ?= tr

.check_%:
#
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

#
# libs
#

LIB_ELF ?= libelf
LIB_ZLIB ?= zlib

define pkg_config
	$(CMD_PKGCONFIG) --libs $(1)
endef

.checklib_%: \
	| .check_$(CMD_PKGCONFIG)
#
	@$(CMD_PKGCONFIG) --silence-errors --validate $* 2>/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing lib $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

.checkver_$(CMD_CLANG): \
	| .check_$(CMD_CLANG)
#
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	touch $@ # avoid target rebuilds over and over due to inexistent file

GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

.checkver_$(CMD_GO): \
	| .check_$(CMD_GO)
#
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 18 ]; then
			echo -n "you MUST use golang 1.18 or newer, "
			echo "your current golang version is ${GO_VERSION}"
			exit 1
		fi
	fi
	touch $@

#
# version
#

LAST_GIT_TAG ?= $(shell $(CMD_GIT) describe --tags --match 'v*' 2>/dev/null)
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(LAST_GIT_TAG))

#
# environment
#

DEBUG ?= 0
UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

ifeq ($(DEBUG),1)
	GO_DEBUG_FLAG =
else
	GO_DEBUG_FLAG = -w
endif

ifeq ($(UNAME_M),x86_64)
	ARCH = x86_64
	LINUX_ARCH = x86
	GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
	ARCH = arm64
	LINUX_ARCH = arm64
	GO_ARCH = arm64
endif

.PHONY: env
env:
	@echo ---------------------------------------
	@echo "Makefile Environment:"
	@echo ---------------------------------------
	@echo "PARALLEL                 $(PARALLEL)"
	@echo ---------------------------------------
	@echo "CLANG_VERSION            $(CLANG_VERSION)"
	@echo "GO_VERSION               $(GO_VERSION)"
	@echo ---------------------------------------
	@echo "CMD_AWK                  $(CMD_AWK)"
	@echo "CMD_CAT                  $(CMD_CAT)"
	@echo "CMD_CLANG                $(CMD_CLANG)"
	@echo "CMD_CUT                  $(CMD_CUT)"
	@echo "CMD_ERRCHECK             $(CMD_ERRCHECK)"
	@echo "CMD_GIT                  $(CMD_GIT)"
	@echo "CMD_GO                   $(CMD_GO)"
	@echo "CMD_GREP                 $(CMD_GREP)"
	@echo "CMD_INSTALL              $(CMD_INSTALL)"
	@echo "CMD_LLC                  $(CMD_LLC)"
	@echo "CMD_MD5                  $(CMD_MD5)"
	@echo "CMD_MKDIR                $(CMD_MKDIR)"
	@echo "CMD_OPA                  $(CMD_OPA)"
	@echo "CMD_PKGCONFIG            $(CMD_PKGCONFIG)"
	@echo "CMD_RM                   $(CMD_RM)"
	@echo "CMD_SED                  $(CMD_SED)"
	@echo "CMD_STATICCHECK          $(CMD_STATICCHECK)"
	@echo "CMD_STRIP                $(CMD_STRIP)"
	@echo "CMD_TOUCH                $(CMD_TOUCH)"
	@echo "CMD_TR                   $(CMD_TR)"
	@echo ---------------------------------------
	@echo "LIB_ELF                  $(LIB_ELF)"
	@echo "LIB_ZLIB                 $(LIB_ZLIB)"
	@echo ---------------------------------------
	@echo "VERSION                  $(VERSION)"
	@echo "LAST_GIT_TAG             $(LAST_GIT_TAG)"
	@echo ---------------------------------------
	@echo "UNAME_M                  $(UNAME_M)"
	@echo "UNAME_R                  $(UNAME_R)"
	@echo "ARCH                     $(ARCH)"
	@echo "LINUX_ARCH               $(LINUX_ARCH)"
	@echo ---------------------------------------
	@echo "OUTPUT_DIR               $(OUTPUT_DIR)"
	@echo ---------------------------------------
	@echo "LIBBPF_CFLAGS            $(LIBBPF_CFLAGS)"
	@echo "LIBBPF_LDLAGS            $(LIBBPF_LDFLAGS)"
	@echo "LIBBPF_SRC               $(LIBBPF_SRC)"
	@echo ---------------------------------------
	@echo "STATIC                   $(STATIC)"
	@echo ---------------------------------------
	@echo "BPF_VCPU                 $(BPF_VCPU)"
	@echo "TRACEE_EBPF_OBJ_SRC      $(TRACEE_EBPF_OBJ_SRC)"
	@echo "TRACEE_EBPF_OBJ_HEADERS  $(TRACEE_EBPF_OBJ_HEADERS)"
	@echo ---------------------------------------
	@echo "GO_ARCH                  $(GO_ARCH)"
	@echo "GO_TAGS_EBPF             $(GO_TAGS_EBPF)"
	@echo "GO_TAGS_RULES            $(GO_TAGS_RULES)"
	@echo ---------------------------------------
	@echo "DEBUG                    $(DEBUG)"
	@echo "GO_DEBUG_FLAG            $(GO_DEBUG_FLAG)"
	@echo ---------------------------------------
	@echo "CUSTOM_CGO_CFLAGS        $(CUSTOM_CGO_CFLAGS)"
	@echo "CUSTOM_CGO_LDFLAGS       $(CUSTOM_CGO_LDFLAGS)"
	@echo "CGO_EXT_LDFLAGS_EBPF     $(CGO_EXT_LDFLAGS_EBPF)"
	@echo "CGO_EXT_LDFLAGS_RULES    $(CGO_EXT_LDFLAGS_RULES)"
	@echo ---------------------------------------
	@echo "GO_ENV_EBPF              $(GO_ENV_EBPF)"
	@echo "GO_ENV_RULES             $(GO_ENV_RULES)"
	@echo ---------------------------------------
	@echo "TRACEE_SRC               $(TRACEE_SRC)"
	@echo "TRACEE_SRC_DIRS          $(TRACEE_SRC_DIRS)"
	@echo ---------------------------------------
	@echo "TRACEE_RULES_SRC_DIRS    $(TRACEE_RULES_SRC_DIRS)"
	@echo "TRACEE_RULES_SRC         $(TRACEE_RULES_SRC)"
	@echo ---------------------------------------
	@echo "TRACEE_BENCH_SRC_DIRS    $(TRACEE_BENCH_SRC_DIRS)"
	@echo "TRACEE_BENCH_SRC         $(TRACEE_BENCH_SRC)"
	@echo ---------------------------------------
	@echo "TRACEE_GPTDOCS_SRC_DIRS  $(TRACEE_GPTDOCS_SRC_DIRS)"
	@echo "TRACEE_GPTDOCS_SRC       $(TRACEE_GPTDOCS_SRC)"
	@echo ---------------------------------------
	@echo "GOSIGNATURES_DIR         $(GOSIGNATURES_DIR)"
	@echo "GOSIGNATURES_SRC         $(GOSIGNATURES_SRC)"
	@echo ---------------------------------------
	@echo "REGO_SIGNATURES_DIR      $(REGO_SIGNATURES_DIR)"
	@echo "REGO_SIGNATURES_SRC      $(REGO_SIGNATURES_SRC)"
	@echo ---------------------------------------
	@echo "E2E_NET_DIR              $(E2E_NET_DIR)"
	@echo "E2E_NET_SRC              $(E2E_NET_SRC)"
	@echo "E2E_INST_DIR             $(E2E_INST_DIR)"
	@echo "E2E_INST_SRC             $(E2E_INST_SRC)"
	@echo ---------------------------------------

#
# usage
#

.PHONY: help
help:
	@echo ""
	@echo "# environment"
	@echo ""
	@echo "    $$ make env                      # show makefile environment/variables"
	@echo ""
	@echo "# build"
	@echo ""
	@echo "    $$ make all                      		# build tracee-ebpf, tracee-rules & signatures"
	@echo "    $$ make bpf                      		# build ./dist/tracee.bpf.o"
	@echo "    $$ make tracee-ebpf              		# build ./dist/tracee-ebpf"
	@echo "    $$ make tracee-rules             		# build ./dist/tracee-rules"
	@echo "    $$ make tracee-bench             		# build ./dist/tracee-bench"
	@echo "    $$ make tracee-gptdocs             		# build ./dist/tracee-gptdocs"
	@echo "    $$ make signatures               		# build ./dist/signatures"
	@echo "    $$ make e2e-net-signatures       		# build ./dist/e2e-net-signatures"
	@echo "    $$ make e2e-instrumentation-signatures	# build ./dist/e2e-instrumentation-signatures"
	@echo "    $$ make tracee                   		# build ./dist/tracee"
	@echo ""
	@echo "# clean"
	@echo ""
	@echo "    $$ make clean                    # wipe ./dist/"
	@echo "    $$ make clean-bpf                # wipe ./dist/tracee.bpf.o"
	@echo "    $$ make clean-tracee-ebpf        # wipe ./dist/tracee-ebpf"
	@echo "    $$ make clean-tracee-rules       # wipe ./dist/tracee-rules"
	@echo "    $$ make clean-tracee-bench       # wipe ./dist/tracee-bench"
	@echo "    $$ make clean-signatures         # wipe ./dist/signatures"
	@echo "    $$ make clean-tracee             # wipe ./dist/tracee"
	@echo ""
	@echo "# test"
	@echo ""
	@echo "    $$ make test-unit                # run unit tests"
	@echo "    $$ make test-types               # run unit tests for types module"
	@echo "    $$ make test-integration         # run integration tests"
	@echo "    $$ make test-signatures          # opa test (tracee-rules)"
	@echo ""
	@echo "# flags"
	@echo ""
	@echo "    $$ STATIC=1 make ...             # build static binaries"
	@echo "    $$ BTFHUB=1 STATIC=1 make ...    # build static binaries, embed BTF"
	@echo "    $$ DEBUG=1 make ...              # build binaries with debug symbols"
	@echo ""

#
# variables
#

BPF_VCPU = v2

#
# output dir
#

OUTPUT_DIR = ./dist

$(OUTPUT_DIR):
#
	@$(CMD_MKDIR) -p $@
	$(CMD_MKDIR) -p $@/libbpf
	$(CMD_MKDIR) -p $@/libbpf/obj

#
# embedded btfhub
#

$(OUTPUT_DIR)/btfhub:
#
	@$(CMD_MKDIR) -p $@
	$(CMD_TOUCH) $@/.place-holder

#
# libbpf (statically linked)
#

LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDLAGS =
LIBBPF_SRC = ./3rdparty/libbpf/src

$(OUTPUT_DIR)/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \
	| .checkver_$(CMD_CLANG) $(OUTPUT_DIR)
#
	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/) \
		OBJDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/obj) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers

$(LIBBPF_SRC): \
	| .check_$(CMD_GIT)
#
ifeq ($(wildcard $@), )
	@$(CMD_GIT) submodule update --init --recursive
endif

#
# ebpf object
#

TRACEE_EBPF_OBJ_SRC = ./pkg/ebpf/c/tracee.bpf.c
TRACEE_EBPF_OBJ_HEADERS = $(shell find pkg/ebpf/c -name *.h)

.PHONY: bpf
bpf: $(OUTPUT_DIR)/tracee.bpf.o

$(OUTPUT_DIR)/tracee.bpf.o: \
	$(OUTPUT_DIR)/libbpf/libbpf.a \
	$(TRACEE_EBPF_OBJ_SRC) \
	$(TRACEE_EBPF_OBJ_HEADERS)
#
	$(CMD_CLANG) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		-DCORE \
		-I./pkg/ebpf/c/ \
		-I$(OUTPUT_DIR)/libbpf/ \
		-I ./3rdparty/include \
		-target bpf \
		-O2 -g \
		-march=bpf -mcpu=$(BPF_VCPU) \
		-c $(TRACEE_EBPF_OBJ_SRC) \
		-o $@

.PHONY: clean-bpf
clean-bpf:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee.bpf.o

#
# common variables
#

STATIC ?= 0
GO_TAGS_EBPF = core,ebpf
CGO_EXT_LDFLAGS_EBPF =

ifeq ($(STATIC), 1)
    CGO_EXT_LDFLAGS_EBPF += -static
    GO_TAGS_EBPF := $(GO_TAGS_EBPF),netgo
endif

TRACEE_SRC_DIRS = ./cmd/ ./pkg/ ./signatures/
TRACEE_SRC = $(shell find $(TRACEE_SRC_DIRS) -type f -name '*.go' ! -name '*_test.go')

CUSTOM_CGO_CFLAGS = "-I$(abspath $(OUTPUT_DIR)/libbpf)"
CUSTOM_CGO_LDFLAGS = "$(shell $(call pkg_config, $(LIB_ELF))) $(shell $(call pkg_config, $(LIB_ZLIB))) $(abspath $(OUTPUT_DIR)/libbpf/libbpf.a)"

GO_ENV_EBPF =
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += CC=$(CMD_CLANG)
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_EBPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)

#
# btfhub (expensive: only run if ebpf obj changed)
#

SH_BTFHUB = ./3rdparty/btfhub.sh

.PHONY: btfhub
btfhub: \
	$(OUTPUT_DIR)/tracee.bpf.o \
	| .check_$(CMD_MD5)
#
ifeq ($(BTFHUB), 1)
	@new=$($(CMD_MD5) -b $< | cut -d' ' -f1)
	@if [ -f ".$(notdir $<).md5" ]; then
		old=$($(CMD_CAT) .$(notdir $<).md5)
		if [ "$$old" != "$$new" ]; then
			$(SH_BTFHUB) && echo $$new > .$(notdir $<).md5
		fi
	else
		$(SH_BTFHUB) && echo $$new > .$(notdir $<).md5
	fi
endif

#
# tracee (single binary)
#

.PHONY: tracee
tracee: $(OUTPUT_DIR)/tracee

$(OUTPUT_DIR)/tracee: \
	$(OUTPUT_DIR)/tracee.bpf.o \
	$(TRACEE_SRC) \
	| .checkver_$(CMD_GO) \
	.checklib_$(LIB_ELF) \
	.checklib_$(LIB_ZLIB) \
	btfhub \
	signatures
#
	$(MAKE) $(OUTPUT_DIR)/btfhub
	$(MAKE) btfhub
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X github.com/aquasecurity/tracee/cmd/tracee/cmd.version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/tracee

.PHONY: clean-tracee
clean-tracee:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee
	$(CMD_RM) -rf .*.md5

#
# tracee-ebpf (deprecated)
#

.PHONY: tracee-ebpf
tracee-ebpf: $(OUTPUT_DIR)/tracee-ebpf

$(OUTPUT_DIR)/tracee-ebpf: \
	$(OUTPUT_DIR)/tracee.bpf.o \
	$(TRACEE_SRC) \
	| .checkver_$(CMD_GO) \
	.checklib_$(LIB_ELF) \
	.checklib_$(LIB_ZLIB) \
	btfhub
#
	$(MAKE) $(OUTPUT_DIR)/btfhub
	$(MAKE) btfhub
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/tracee-ebpf

.PHONY: clean-tracee-ebpf
clean-tracee-ebpf:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-ebpf
	$(CMD_RM) -rf .*.md5

#
# tracee-rules (deprecated)
#

STATIC ?= 0
GO_TAGS_RULES =
CGO_EXT_LDFLAGS_RULES =

ifeq ($(STATIC), 1)
    CGO_EXT_LDFLAGS_RULES += -static
    GO_TAGS_RULES := netgo
endif

GO_ENV_RULES =
GO_ENV_RULES += GOOS=linux
GO_ENV_RULES += CC=$(CMD_CLANG)
GO_ENV_RULES += GOARCH=$(GO_ARCH)
GO_ENV_RULES += CGO_CFLAGS=
GO_ENV_RULES += CGO_LDFLAGS=

TRACEE_RULES_SRC_DIRS = ./cmd/tracee-rules/ ./pkg/signatures/
TRACEE_RULES_SRC=$(shell find $(TRACEE_RULES_SRC_DIRS) -type f -name '*.go')

.PHONY: tracee-rules
tracee-rules: $(OUTPUT_DIR)/tracee-rules

$(OUTPUT_DIR)/tracee-rules: \
	.checkver_$(CMD_GO) \
	$(TRACEE_RULES_SRC) \
	| $(OUTPUT_DIR) \
	signatures
#
	$(GO_ENV_RULES) $(CMD_GO) build \
		-tags $(GO_TAGS_RULES) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_RULES)\" \
			" \
		-v -o $@ \
		./cmd/tracee-rules

.PHONY: clean-tracee-rules
clean-tracee-rules:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-rules

#
# signatures
#

GOSIGNATURES_DIR ?= signatures/golang
GOSIGNATURES_SRC :=	$(shell find $(GOSIGNATURES_DIR) \
			-type f \
			-name '*.go' \
			! -name '*_test.go' \
			! -path '$(GOSIGNATURES_DIR)/examples/*' \
			)

REGO_SIGNATURES_DIR ?= signatures/rego
REGO_SIGNATURES_SRC :=	$(shell find $(REGO_SIGNATURES_DIR) \
			-type f \
			-name '*.rego' \
			! -name '*_test.rego' \
			! -path '$(REGO_SIGNATURES_DIR)/examples/*' \
			)

.PHONY: signatures
signatures: $(OUTPUT_DIR)/signatures

$(OUTPUT_DIR)/signatures: \
	$(GOSIGNATURES_SRC) \
	$(REGO_SIGNATURES_SRC) \
	| .checkver_$(CMD_GO) \
	.check_$(CMD_INSTALL) \
	$(OUTPUT_DIR)
#
	$(CMD_MKDIR) -p $@
	$(GO_ENV_RULES) $(CMD_GO) build \
		--buildmode=plugin \
		-o $@/builtin.so \
		$(GOSIGNATURES_SRC)
	# disable rego signatures by default (keep golang signatures only)
	# $(CMD_INSTALL) -m 0644 $(REGO_SIGNATURES_SRC) $@

.PHONY: clean-signatures
clean-signatures:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/signatures

#
# other commands
#

# tracee-bench

TRACEE_BENCH_SRC_DIRS = ./cmd/tracee-bench/
TRACEE_BENCH_SRC = $(shell find $(TRACEE_BENCH_SRC_DIRS) \
			-type f \
			-name '*.go' \
			! -name '*_test.go' \
			)

.PHONY: tracee-bench
tracee-bench: $(OUTPUT_DIR)/tracee-bench

$(OUTPUT_DIR)/tracee-bench: \
	.checkver_$(CMD_GO) \
	$(TRACEE_BENCH_SRC) \
	| $(OUTPUT_DIR)
#
	$(CMD_GO) build \
		-v -o $@ \
		./cmd/tracee-bench

.PHONY: clean-tracee-bench
clean-tracee-bench:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-bench

# tracee-gptdocs

TRACEE_GPTDOCS_SRC_DIRS = ./cmd/tracee-gptdocs/ ./pkg/cmd/
TRACEE_GPTDOCS_SRC = $(shell find $(TRACEE_GPTDOCS_SRC_DIRS) \
			-type f \
			-name '*.go' \
			! -name '*_test.go' \
			)

.PHONY: tracee-gptdocs
tracee-gptdocs: $(OUTPUT_DIR)/tracee-gptdocs

$(OUTPUT_DIR)/tracee-gptdocs: \
	.checkver_$(CMD_GO) \
	$(TRACEE_GPTDOCS_SRC) \
	| $(OUTPUT_DIR)
#
	$(MAKE) $(OUTPUT_DIR)/btfhub
	$(MAKE) btfhub
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/tracee-gptdocs

.PHONY: clean-tracee-gptdocs
clean-tracee-gptdocs:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-gptdocs

#
# functional tests (using test signatures)
#

# e2e network signatures

E2E_NET_DIR ?= tests/e2e-net-signatures
E2E_NET_SRC := $(shell find $(E2E_NET_DIR) \
		-type f \
		-name '*.go' \
		! -name '*_test.go' \
		)

.PHONY: e2e-net-signatures
e2e-net-signatures: $(OUTPUT_DIR)/e2e-net-signatures

$(OUTPUT_DIR)/e2e-net-signatures: \
	$(E2E_NET_SRC) \
	| .checkver_$(CMD_GO) \
	.check_$(CMD_INSTALL) \
	$(OUTPUT_DIR)
#
	$(CMD_MKDIR) -p $@
	$(GO_ENV_RULES) $(CMD_GO) build \
		--buildmode=plugin \
		-o $@/builtin.so \
		$(E2E_NET_SRC)

.PHONY: clean-e2e-net-signatures
clean-e2e-net-signatures:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/e2e-net-signatures

# e2e instrumentation signatures

E2E_INST_DIR ?= tests/e2e-instrumentation-signatures
E2E_INST_SRC := $(shell find $(E2E_INST_DIR) \
		-type f \
		-name '*.go' \
		! -name '*_test.go' \
		)

.PHONY: e2e-instrumentation-signatures
e2e-instrumentation-signatures: $(OUTPUT_DIR)/e2e-instrumentation-signatures

$(OUTPUT_DIR)/e2e-instrumentation-signatures: \
	$(E2E_INST_SRC) \
	| .checkver_$(CMD_GO) \
	.check_$(CMD_INSTALL) \
	$(OUTPUT_DIR)
#
	$(CMD_MKDIR) -p $@
	$(GO_ENV_RULES) $(CMD_GO) build \
		--buildmode=plugin \
		-o $@/builtin.so \
		$(E2E_INST_SRC)

.PHONY: clean-e2e-instrumentation-signatures
clean-e2e-instrumentation-signatures:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/e2e-instrumentation-signatures

#
# tests
#

.PHONY: test-unit
test-unit: \
	.checkver_$(CMD_GO) \
	tracee-ebpf \
	test-types
#
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags ebpf \
		-short \
		-race \
		-v \
		-coverprofile=coverage.txt \
		./cmd/... \
		./pkg/... \
		./signatures/... \

.PHONY: test-types
test-types: \
	.checkver_$(CMD_GO)
#
	# Note that we must changed the directory here because types is a standalone Go module.
	cd ./types && $(CMD_GO) test \
		-short \
		-race \
		-v \
		-coverprofile=coverage.txt \
		./...

.PHONY: test-integration
test-integration: \
	.checkver_$(CMD_GO) \
	tracee-ebpf
#
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-v \
		-p 1 \
		-count=1 \
		./tests/integration/... \

.PHONY: test-signatures
test-signatures: \
	| .check_$(CMD_OPA)
#
	$(CMD_OPA) test $(REGO_SIGNATURES_DIR) --verbose

.PHONY: test-upstream-libbpfgo
test-upstream-libbpfgo: \
	.checkver_$(CMD_GO) \
	$(OUTPUT_DIR)/libbpf/libbpf.a
#
	./tests/libbpfgo.sh $(GO_ENV_EBPF)

#
# code checkers (hidden from help on purpose)
#

.PHONY: check-fmt
check-fmt::
#
	@$(MAKE) -f builder/Makefile.checkers fmt-check

.PHONY: fix-fmt
fix-fmt::
#
	@$(MAKE) -f builder/Makefile.checkers fmt-fix

.PHONY: check-lint
check-lint::
#
	@$(MAKE) -f builder/Makefile.checkers lint-check

.PHONY: check-code
check-code:: \
	tracee-ebpf
#
	@$(MAKE) -f builder/Makefile.checkers code-check


.PHONY: check-vet
check-vet: \
	.checkver_$(CMD_GO) \
	tracee-ebpf
#
	@$(GO_ENV_EBPF) \
	$(CMD_GO) vet \
		-tags $(GO_TAGS_EBPF) \
		./...

.PHONY: check-staticcheck
check-staticcheck: \
	.checkver_$(CMD_GO) \
	tracee-ebpf \
	| .check_$(CMD_STATICCHECK)
#
	@$(GO_ENV_EBPF) \
	$(CMD_STATICCHECK) -f stylish \
		-tags $(GO_TAGS_EBPF) \
		./...

.PHONY: check-err
check-err: \
	.checkver_$(CMD_GO) \
	tracee-ebpf \
	| .check_$(CMD_ERRCHECK)
#
	@$(CMD_ERRCHECK) \
		-tags $(GO_TAGS_EBPF) \
		-ignoretests \
		-ignore 'fmt:[FS]?[Pp]rint*|[wW]rite' \
		-ignore '[rR]ead|[wW]rite' \
		-ignore 'RegisterEventProcessor' \
		./...

#
# clean
#

.PHONY: clean
clean:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)
	$(CMD_RM) -f .*.md5
	$(CMD_RM) -f .check*
	$(CMD_RM) -f .*-pkgs*
