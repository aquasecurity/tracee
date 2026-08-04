.PHONY: all env
all:: signatures tracee evt traceectl lsm-check

#
# make
#

.ONESHELL:
SHELL = /bin/sh

BUILD_TYPE_FLAG := COMMON_BUILD
GO_TAGS_EBPF := core,ebpf,lsmsupport
# static analysis / unit tests: the ebpfstub tag swaps the go:embed of built
# BPF artifacts for empty stubs, so nothing in dist/ needs to exist
GO_TAGS_EBPF_CHECK = $(GO_TAGS_EBPF),ebpfstub

# Go 1.26 randomizes the heap base address, which breaks the eBPF stack_pivot
# detector's Go heap recognition (vma_is_golang_heap in common/memory.h relies
# on arenas starting at 0xc000000000). Disable until the eBPF code is updated
# to handle randomized heap bases.
export GOEXPERIMENT ?= norandomizedheapbase64

EXCLUDED_MODULES := ./3rdparty/*

# load extended-pre Makefile, if exists
-include Makefile.extended-pre

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
MAKE = make
MAKEFLAGS += --no-print-directory

#
# env
#

OUTPUT_DIR = ./dist

# context-keyed build state: stamps and the cgo env cache encode absolute
# paths and tool versions of the environment they were created in (container
# /tracee vs host tree, alpine vs ubuntu), so each context gets its own dir
BUILD_CONTEXT ?= host
# no leading ./ - make normalizes prerequisite paths, which would break
# pattern-rule matching against $(STAMPS_DIR)/.check_%
STAMPS_DIR = $(patsubst ./%,%,$(OUTPUT_DIR))/.ctx/$(BUILD_CONTEXT)

GOENV_MK = $(STAMPS_DIR)/goenv.mk

# load Go environment variables
-include $(GOENV_MK)

#
# tools
#

CMD_AWK ?= awk
CMD_BEAR ?= bear
CMD_CAT ?= cat
CMD_CLANG ?= clang
CMD_CP ?= cp
CMD_CUT ?= cut
CMD_ERRCHECK ?= errcheck
CMD_GCC ?= gcc
CMD_GOVULNCHECK ?= govulncheck
CMD_GIT ?= git
CMD_GO ?= go
CMD_GREP ?= grep
CMD_INSTALL ?= install
CMD_LLC ?= llc
CMD_MD5 ?= md5sum
CMD_MKDIR ?= mkdir
CMD_PKGCONFIG ?= pkg-config
CMD_RM ?= rm
CMD_SED ?= sed
CMD_STATICCHECK ?= staticcheck
CMD_STRIP ?= llvm-strip
CMD_OBJCOPY ?= llvm-objcopy
CMD_TOUCH ?= touch
CMD_TR ?= tr
CMD_PROTOC ?= protoc
CMD_PANDOC ?= pandoc
CMD_CONTROLLER_GEN ?= controller-gen

$(STAMPS_DIR)/.check_%:
#
	@$(CMD_MKDIR) -p $(@D)
	command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to non-existing file
	fi

#
# libs
#

LIB_BPF ?= libbpf

# Recursively get private requirements of a library.
# It ignores libbpf as it is in 3rdparty, but considers its requirements.
fetch_priv_reqs_recursive = \
get_priv_reqs_recursive() { \
	lib=$$1; \
	processed_libs=$$2; \
	if echo "$$processed_libs" | grep -qw "$$lib"; then \
		return; \
	fi; \
	processed_libs="$$processed_libs $$lib"; \
	if [ "$$lib" = "libbpf" ]; then \
		priv_reqs=$$(PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(CMD_PKGCONFIG) --print-requires-private $$lib); \
	else \
		echo $$lib; \
		priv_reqs=$$($(CMD_PKGCONFIG) --print-requires-private $$lib); \
	fi; \
	for req in $$priv_reqs; do \
		if echo "$$processed_libs" | grep -qw "$$req"; then \
			continue; \
		fi; \
	done; \
	for req in $$priv_reqs; do \
		get_priv_reqs_recursive $$req "$$processed_libs"; \
	done; \
}; \
\
get_all_priv_reqs() { \
	lib=$$1; \
	get_priv_reqs_recursive $$lib ""; \
}; \
\
get_all_priv_reqs $$1

$(STAMPS_DIR)/.checklib_%: \
	| $(STAMPS_DIR)/.check_$(CMD_PKGCONFIG)
#
	@{ \
		$(eval required_libs := $(shell sh -c '$(fetch_priv_reqs_recursive) $*'))
		$(eval output := $(shell sh -c '\
		for lib in "$(required_libs)"; do \
			$(CMD_PKGCONFIG) --silence-errors --validate $$lib 2>/dev/null || echo "$$lib"; \
		done'))
		if [ -n "$(output)" ]; then \
			echo "missing required library: $(output)"; \
			exit 1; \
		fi; \
	} && $(CMD_MKDIR) -p $(@D) && touch $@ # avoid target rebuilds due to non-existing file

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

$(STAMPS_DIR)/.checkver_$(CMD_CLANG):: \
	| $(STAMPS_DIR)/.check_$(CMD_CLANG)
#
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	$(CMD_MKDIR) -p $(@D)
	touch $@ # avoid target rebuilds over and over due to non-existing file

GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

$(STAMPS_DIR)/.checkver_$(CMD_GO):: \
	| $(STAMPS_DIR)/.check_$(CMD_GO)
#
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 18 ]; then
			echo -n "you MUST use golang 1.18 or newer, "
			echo "your current golang version is ${GO_VERSION}"
			exit 1
		fi
	fi
	$(CMD_MKDIR) -p $(@D)
	touch $@

#
# version
#

# LAST_GIT format: <branch>-<commit>
LAST_GIT ?= $(shell $(CMD_GIT) symbolic-ref --short HEAD 2>/dev/null)-$(shell $(CMD_GIT) rev-parse --short HEAD)
VERSION ?= $(if $(RELEASE_VERSION),$(RELEASE_VERSION),$(LAST_GIT))

#
# environment
#

DEBUG ?= 0
FIPS ?= 0
UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

ifeq ($(DEBUG),1)
	GO_DEBUG_FLAG =
else
	GO_DEBUG_FLAG = -w
endif

ifeq ($(METRICS),1)
	BPF_DEBUG_FLAG += -DMETRICS
endif

# FIPS 140-3 compliance
ifeq ($(FIPS),1)
	GOFIPS140 = v1.0.0
else
	GOFIPS140 = off
endif

# Strip debug symbols from BPF object
STRIP_BPF_DEBUG ?= 0

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

# TODO(#5287): re-enable -race on arm64 once golang/go#78573 is fixed.
# Go 1.26.2 ships a race_linux_arm64.syso whose TSAN runtime references
# LSE outline-atomics symbols (__aarch64_*_sync) that clang 19 / compiler-rt
# cannot resolve, breaking every -race link on aarch64.
ifneq ($(GO_ARCH),arm64)
	GO_TEST_RACE ?= -race
endif

.PHONY: env
env::
	@echo ---------------------------------------
	@echo "Makefile Environment:"
	@echo ---------------------------------------
	@echo "PARALLEL                 $(PARALLEL)"
	@echo ---------------------------------------
	@echo "CLANG_VERSION            $(CLANG_VERSION)"
	@echo "GO_VERSION               $(GO_VERSION)"
	@echo ---------------------------------------
	@echo "CMD_AWK                  $(CMD_AWK)"
	@echo "CMD_BEAR                 $(CMD_BEAR)"
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
	@echo "CMD_PKGCONFIG            $(CMD_PKGCONFIG)"
	@echo "CMD_RM                   $(CMD_RM)"
	@echo "CMD_SED                  $(CMD_SED)"
	@echo "CMD_STATICCHECK          $(CMD_STATICCHECK)"
	@echo "CMD_STRIP                $(CMD_STRIP)"
	@echo "CMD_OBJCOPY              $(CMD_OBJCOPY)"
	@echo "CMD_TOUCH                $(CMD_TOUCH)"
	@echo "CMD_TR                   $(CMD_TR)"
	@echo "CMD_PROTOC               $(CMD_PROTOC)"
	@echo ---------------------------------------
	@echo "LIB_BPF                  $(LIB_BPF)"
	@echo ---------------------------------------
	@echo "VERSION                  $(VERSION)"
	@echo "LAST_GIT                 $(LAST_GIT)"
	@echo ---------------------------------------
	@echo "UNAME_M                  $(UNAME_M)"
	@echo "UNAME_R                  $(UNAME_R)"
	@echo "ARCH                     $(ARCH)"
	@echo "LINUX_ARCH               $(LINUX_ARCH)"
	@echo ---------------------------------------
	@echo "OUTPUT_DIR               $(OUTPUT_DIR)"
	@echo ---------------------------------------
	@echo "LIBBPF_CFLAGS            $(LIBBPF_CFLAGS)"
	@echo "LIBBPF_LDFLAGS           $(LIBBPF_LDFLAGS)"
	@echo "LIBBPF_SRC               $(LIBBPF_SRC)"
	@echo ---------------------------------------
	@echo "STATIC                   $(STATIC)"
	@echo ---------------------------------------
	@echo "BPF_VCPU                 $(BPF_VCPU)"
	@echo "TRACEE_EBPF_CFLAGS       $(TRACEE_EBPF_CFLAGS)"
	@echo "TRACEE_EBPF_OBJ_SRC      $(TRACEE_EBPF_OBJ_SRC)"
	@echo "TRACEE_EBPF_OBJ_HEADERS  $(TRACEE_EBPF_OBJ_HEADERS)"
	@echo ---------------------------------------
	@echo "GO_ARCH                  $(GO_ARCH)"
	@echo "GO_TAGS_EBPF             $(GO_TAGS_EBPF)"
	@echo "GO_TAGS_E2E              $(GO_TAGS_E2E)"
	@echo "GO_TAGS_E2E_NET          $(GO_TAGS_E2E_NET)"
	@echo "GO_TAGS_RULES            $(GO_TAGS_RULES)"
	@echo ---------------------------------------
	@echo "DEBUG                    $(DEBUG)"
	@echo "GO_DEBUG_FLAG            $(GO_DEBUG_FLAG)"
	@echo "STRIP_BPF_DEBUG          $(STRIP_BPF_DEBUG)"
	@echo ---------------------------------------
	@echo "FIPS                     $(FIPS)"
	@echo "GOFIPS140                $(GOFIPS140)"
	@echo ---------------------------------------
	@echo "CUSTOM_CGO_CFLAGS        $(CUSTOM_CGO_CFLAGS)"
	@echo "CUSTOM_CGO_LDFLAGS       $(CUSTOM_CGO_LDFLAGS)"
	@echo "CGO_EXT_LDFLAGS_EBPF     $(CGO_EXT_LDFLAGS_EBPF)"
	@echo "CGO_EXT_LDFLAGS_RULES    $(CGO_EXT_LDFLAGS_RULES)"
	@echo ---------------------------------------
	@echo "GO_ENV_EBPF              $(GO_ENV_EBPF)"
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
	@echo "GOSIGNATURES_DIR         $(GOSIGNATURES_DIR)"
	@echo "GOSIGNATURES_SRC         $(GOSIGNATURES_SRC)"
	@echo ---------------------------------------
	@echo ---------------------------------------
	@echo "TRACEE_PROTOS            $(TRACEE_PROTOS)"
	@echo ---------------------------------------
	@echo "SCRIPTS_TEST_DIR         $(SCRIPTS_TEST_DIR)"
	@echo ---------------------------------------


#
# variables
#

BPF_VCPU = v2

#
# output dir
#

$(OUTPUT_DIR)::
#
	@$(CMD_MKDIR) -p $@
	$(CMD_MKDIR) -p $(LIBBPF_OBJDIR)


#
# embedded directories required by different targets
#

.PHONY: embedded-dirs
embedded-dirs:: $(OUTPUT_DIR)/btfhub $(OUTPUT_DIR)/lsm_support

#
# embedded btfhub
#

$(OUTPUT_DIR)/btfhub::
#
	@$(CMD_MKDIR) -p $@
	$(CMD_TOUCH) $@/.place-holder

#
# libbpf (statically linked)
#

LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDFLAGS =
LIBBPF_SRC = ./3rdparty/libbpf/src
# context-keyed: the static lib differs per libc (musl vs glibc) and
# libbpf.pc encodes the absolute build prefix (container /tracee vs host
# tree), so contexts sharing one output dir would poison each other
LIBBPF_DESTDIR = $(STAMPS_DIR)/libbpf
LIBBPF_OBJDIR = $(LIBBPF_DESTDIR)/obj
LIBBPF_OBJ = $(LIBBPF_OBJDIR)/libbpf.a

$(LIBBPF_OBJ):: $(STAMPS_DIR)/.build_libbpf $(STAMPS_DIR)/.build_libbpf_fix

$(STAMPS_DIR)/.build_libbpf:: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \
	| $(STAMPS_DIR)/.checkver_$(CMD_CLANG)
#
	@$(CMD_MKDIR) -p $(@D)
	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		PREFIX=$(abspath $(STAMPS_DIR)) \
		DESTDIR=$(abspath $(LIBBPF_DESTDIR)) \
		OBJDIR=$(abspath $(LIBBPF_OBJDIR)) \
		LIBDIR=/to-be-removed \
		INCLUDEDIR=/include \
		UAPIDIR=/include \
		install install_uapi_headers
	@$(CMD_TOUCH) $@


LIBBPF_INCLUDE_UAPI = ./3rdparty/libbpf/include/uapi/linux

$(STAMPS_DIR)/.build_libbpf_fix:: $(STAMPS_DIR)/.build_libbpf
# copy all uapi headers to the correct location, since libbpf does not install them fully
# see: https://github.com/aquasecurity/tracee/pull/4186
	@$(CMD_CP) $(LIBBPF_INCLUDE_UAPI)/*.h $(LIBBPF_DESTDIR)/include/linux/
# fix libbpf.pc to point to our paths
	@$(CMD_SED) -i 's|^libdir=/to-be-removed$$|libdir=$${prefix}/libbpf/obj|' $(abspath $(LIBBPF_OBJDIR)/libbpf.pc)
	@$(CMD_SED) -i 's|^includedir=$${prefix}/include$$|includedir=$${prefix}/libbpf/include|' $(abspath $(LIBBPF_OBJDIR)/libbpf.pc)
# remove not needed files
	@$(CMD_RM) -rf $(LIBBPF_DESTDIR)/to-be-removed
	@$(CMD_RM) -rf $(LIBBPF_OBJDIR)/staticobjs
	@$(CMD_TOUCH) $@


# headers-only libbpf install for the static analysis targets: they
# type-check cgo packages (headers needed) but never link, so compiling
# libbpf.a would be wasted work. install_headers/install_uapi_headers are
# plain file copies with no build prerequisites.
$(STAMPS_DIR)/.install_libbpf_headers:: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.h)
#
	@$(CMD_MKDIR) -p $(@D)
	$(MAKE) \
		-C $(LIBBPF_SRC) \
		DESTDIR=$(abspath $(LIBBPF_DESTDIR)) \
		INCLUDEDIR=/include \
		UAPIDIR=/include \
		install_headers install_uapi_headers
# copy all uapi headers to the correct location, since libbpf does not install them fully
	@$(CMD_CP) $(LIBBPF_INCLUDE_UAPI)/*.h $(LIBBPF_DESTDIR)/include/linux/
	@$(CMD_TOUCH) $@

# analysis-only cgo env: fixed paths, no pkg-config (which would require the
# full libbpf build for its .pc file)
GO_ENV_EBPF_CHECK = GOOS=linux CC=$(CMD_CLANG) GOARCH=$(GO_ARCH) \
	CGO_CFLAGS="-I$(abspath $(LIBBPF_DESTDIR))/include"

TRACEE_EBPF_CFLAGS = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(CMD_PKGCONFIG) $(PKG_CONFIG_FLAG) --cflags $(LIB_BPF))

$(STAMPS_DIR)/.eval_goenv:: $(LIBBPF_OBJ)
#
	@{
ifeq ($(STATIC), 1)
		$(eval GO_TAGS_EBPF := $(GO_TAGS_EBPF),netgo)
		$(eval CGO_EXT_LDFLAGS_EBPF := $(CGO_EXT_LDFLAGS_EBPF) -static)
		$(eval PKG_CONFIG_FLAG := --static)
endif
		$(eval GO_ENV_EBPF = )
		$(eval GO_ENV_EBPF += GOOS=linux)
		$(eval GO_ENV_EBPF += CC=$(CMD_CLANG))
		$(eval GO_ENV_EBPF += GOARCH=$(GO_ARCH))
		$(eval GO_ENV_EBPF += GOFIPS140=$(GOFIPS140))
		$(eval CUSTOM_CGO_CFLAGS := "$(TRACEE_EBPF_CFLAGS)")
		$(eval GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS))
		$(eval CUSTOM_CGO_LDFLAGS := "$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(CMD_PKGCONFIG) $(PKG_CONFIG_FLAG) --libs $(LIB_BPF))")
		$(eval GO_ENV_EBPF := $(GO_ENV_EBPF) CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS))
		export GO_ENV_EBPF=$(GO_ENV_EBPF)
		$(CMD_MKDIR) -p $(@D)
		echo 'GO_ENV_EBPF := $(GO_ENV_EBPF)' > $(GOENV_MK)
		$(CMD_TOUCH) $@
	}

$(LIBBPF_SRC):: \
	| $(STAMPS_DIR)/.check_$(CMD_GIT)
#
ifeq ($(wildcard $@), )
	@$(CMD_GIT) submodule update --init --recursive
endif

#
# ebpf object
#

TRACEE_EBPF_OBJ_SRC = ./pkg/ebpf/c/tracee.bpf.c
TRACEE_EBPF_OBJ_HEADERS = $(shell find pkg/ebpf/c -name *.h) $(wildcard ./pkg/ebpf/c/tracee.bpf*.c)

# Consider only the first multiarch include directory
# Use gcc -print-multiarch (clang dropped support for this option from LLVM 16)
# See: https://reviews.llvm.org/D133170
MULTIARCH_INCLUDE := $(shell \
    multiarch_dir=$$($(CMD_GCC) -print-multiarch 2> /dev/null | head -n1); \
    include_dir="/usr/include/$${multiarch_dir}"; \
    if [ -d "$${include_dir}" ]; then \
        echo "-I$${include_dir}"; \
    fi)

.PHONY: bpf
bpf:: $(OUTPUT_DIR)/tracee.bpf.o lsmsupport-bpf

# LSM support BPF objects
LSM_SUPPORT_DIR := pkg/ebpf/c/lsmsupport
LSM_SUPPORT_SRCS := $(patsubst %.bpf.c,%,$(notdir $(wildcard $(LSM_SUPPORT_DIR)/*.bpf.c)))
LSM_SUPPORT_HEADERS := $(shell find $(LSM_SUPPORT_DIR) -name *.h)
LSM_SUPPORT_OBJS := $(addprefix $(OUTPUT_DIR)/lsm_support/,$(addsuffix .bpf.o,$(LSM_SUPPORT_SRCS)))

.PHONY: lsmsupport-bpf
lsmsupport-bpf: $(LSM_SUPPORT_OBJS)

# LSM support BPF objects
# keep the source first so $< expands to the .bpf.c file
$(OUTPUT_DIR)/lsm_support/%.bpf.o: \
	$(LSM_SUPPORT_DIR)/%.bpf.c \
	$(LSM_SUPPORT_HEADERS) \
	$(LIBBPF_OBJ) \
	| $(OUTPUT_DIR)/lsm_support
#
	$(CMD_CLANG) \
		$(BPF_DEBUG_FLAG) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		$(TRACEE_EBPF_CFLAGS) \
		$(MULTIARCH_INCLUDE) \
		-I./pkg/ebpf/c/ \
		-target bpf \
		-O2 -g \
		-mcpu=$(BPF_VCPU) \
		-c $< \
		-o $@

# Create lsm_support directory
$(OUTPUT_DIR)/lsm_support:
	@$(CMD_MKDIR) -p $@
	$(CMD_TOUCH) $@/.place-holder

$(OUTPUT_DIR)/tracee.bpf.o:: \
	$(LIBBPF_OBJ) \
	$(TRACEE_EBPF_OBJ_SRC) \
	$(TRACEE_EBPF_OBJ_HEADERS)
#
	$(CMD_CLANG) \
		$(BPF_DEBUG_FLAG) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		-DCORE \
		-D$(BUILD_TYPE_FLAG) \
		$(TRACEE_EBPF_CFLAGS) \
		$(MULTIARCH_INCLUDE) \
		-I./pkg/ebpf/c/ \
		-target bpf \
		-O2 -g \
		-mcpu=$(BPF_VCPU) \
		-c $(TRACEE_EBPF_OBJ_SRC) \
		-o $@
ifeq ($(STRIP_BPF_DEBUG),1)
	$(CMD_OBJCOPY) --strip-debug $@
endif

.PHONY: clean-bpf
clean-bpf:: clean-lsmsupport-bpf
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee.bpf.o

# LSM check CLI
.PHONY: lsm-check
lsm-check:: $(OUTPUT_DIR)/lsm-check

LSM_CHECK_SRC := $(shell find cmd/lsm_support_check -type f -name '*.go')

$(OUTPUT_DIR)/lsm-check:: \
	$(LSM_SUPPORT_OBJS) \
	$(LSM_CHECK_SRC) \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(STAMPS_DIR)/.checklib_$(LIB_BPF)
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags lsmsupport \
		-o $@ \
		./cmd/lsm_support_check

.PHONY: clean-lsm-check
clean-lsm-check::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/lsm-check

.PHONY: clean-lsmsupport-bpf
clean-lsmsupport-bpf:
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/lsm_support/

#
# common variables
#

STATIC ?= 0
TRACEE_SRC_DIRS = ./cmd/ ./pkg/ ./signatures/ ./detectors/
TRACEE_SRC = $(shell find $(TRACEE_SRC_DIRS) -type f -name '*.go' ! -name '*_test.go')
CGO_EXT_LDFLAGS_EBPF =
PKG_CONFIG_PATH = $(LIBBPF_OBJDIR)
PKG_CONFIG_FLAG =

TRACEE_PROTOS_ALL = $(wildcard ./api/v1beta1/*.proto) $(wildcard ./api/v1beta1/datastores/*.proto)
TRACEE_PROTOS_NO_JSON = ./api/v1beta1/event.proto ./api/v1beta1/event_data.proto
TRACEE_PROTOS = $(filter-out $(TRACEE_PROTOS_NO_JSON),$(TRACEE_PROTOS_ALL))

#
# btfhub (expensive: only run if ebpf obj changed)
#

SH_BTFHUB = ./scripts/btfhub.sh

.PHONY: btfhub
btfhub:: $(STAMPS_DIR)/.tracee.bpf.o.md5

$(STAMPS_DIR)/.tracee.bpf.o.md5: \
	$(OUTPUT_DIR)/tracee.bpf.o \
	| $(STAMPS_DIR)/.check_$(CMD_MD5)
#
ifeq ($(BTFHUB), 1)
	@$(CMD_MKDIR) -p $(@D); \
	input="$<"; \
	new="$$(md5sum -b $${input} | cut -d' ' -f1)"; \
	if [ -f $@ ]; then \
		old="$$(cat $@)"; \
		if [ "$${old}" != "$${new}" ]; then \
			echo "[btfhub] hash changed: $${old} => $${new}"; \
			$(SH_BTFHUB) && echo "$${new}" > $@; \
		fi; \
	else \
		echo "[btfhub] no previous hash, running..."; \
		$(SH_BTFHUB) && echo "$${new}" > $@; \
	fi
endif

#
# tracee builds (single binary)
#
# Builds tracee and its e2e test variants using a shared recipe.
# - tracee: production build
# - tracee-e2e: build with general e2e test detectors (build tag: e2e)
# - tracee-e2e-net: build with network e2e test detectors (build tag: e2e_net)
#

GO_TAGS_E2E := $(GO_TAGS_EBPF),e2e
GO_TAGS_E2E_NET := $(GO_TAGS_EBPF),e2e_net

# Shared dependencies for all tracee builds
TRACEE_BUILD_DEPS = \
	$(OUTPUT_DIR)/tracee.bpf.o \
	$(LSM_SUPPORT_OBJS) \
	$(TRACEE_SRC) \
	go.mod \
	go.sum \
	detectors/go.mod \
	detectors/go.sum

TRACEE_BUILD_ORDER_DEPS = \
	$(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(STAMPS_DIR)/.checklib_$(LIB_BPF) \
	btfhub \
	signatures

# Canned recipe for building tracee variants
define TRACEE_BUILD_RECIPE
	$(MAKE) embedded-dirs
	$(MAKE) btfhub
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(TRACEE_BUILD_TAGS) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X github.com/aquasecurity/tracee/pkg/version.version=$(VERSION) \
			-X github.com/aquasecurity/tracee/pkg/version.metrics=$(METRICS) \
			" \
		-v -o $@ \
		./cmd/tracee
endef

# Target-specific build tags
$(OUTPUT_DIR)/tracee: TRACEE_BUILD_TAGS = $(GO_TAGS_EBPF)
$(OUTPUT_DIR)/tracee-e2e: TRACEE_BUILD_TAGS = $(GO_TAGS_E2E)
$(OUTPUT_DIR)/tracee-e2e-net: TRACEE_BUILD_TAGS = $(GO_TAGS_E2E_NET)

# Phony aliases
.PHONY: tracee tracee-e2e tracee-e2e-net
tracee:: $(OUTPUT_DIR)/tracee
tracee-e2e:: $(OUTPUT_DIR)/tracee-e2e
tracee-e2e-net:: $(OUTPUT_DIR)/tracee-e2e-net

# Single rule for all tracee variants
$(OUTPUT_DIR)/tracee $(OUTPUT_DIR)/tracee-e2e $(OUTPUT_DIR)/tracee-e2e-net:: \
	$(TRACEE_BUILD_DEPS) \
	| $(TRACEE_BUILD_ORDER_DEPS)
#
	$(TRACEE_BUILD_RECIPE)

# run tracee with arbitrary arguments (ARG="..."), building it first if
# needed; from the host this dispatches into the privileged build container
# (host kernel, binary consistent with the environment that built it), with
# NATIVE=1 it runs on the host directly
.PHONY: run
run:: tracee
#
	@$(if $(filter 0,$(shell id -u)),,sudo )./dist/tracee $(ARG)

# same pattern for the companion binaries; all share the privileged run
# profile from the host (host kernel/network and /tmp/tracee, so e.g.
# traceectl can reach a tracee started by 'make run')
.PHONY: run-traceectl
run-traceectl:: traceectl
#
	@$(if $(filter 0,$(shell id -u)),,sudo )./dist/traceectl $(ARG)

.PHONY: run-evt
run-evt:: evt
#
	@$(if $(filter 0,$(shell id -u)),,sudo )./dist/evt $(ARG)

# Clean targets
.PHONY: clean-tracee
clean-tracee::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee
	$(CMD_RM) -rf .*.md5

.PHONY: clean-tracee-e2e
clean-tracee-e2e::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-e2e

.PHONY: clean-tracee-e2e-net
clean-tracee-e2e-net::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-e2e-net

# Convenience target for building tracee with example detectors
.PHONY: tracee-with-examples
tracee-with-examples::
#
	$(MAKE) tracee GO_TAGS_EBPF="$(GO_TAGS_EBPF),detectorexamples"

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

$(OUTPUT_DIR)/signatures:: \
	| $(OUTPUT_DIR)
#
	$(CMD_MKDIR) -p $@

.PHONY: signatures
signatures:: \
	$(OUTPUT_DIR)/signatures/builtin.so

$(OUTPUT_DIR)/signatures/builtin.so:: \
	$(GOSIGNATURES_SRC) \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		--buildmode=plugin \
		-o $@ \
		$(GOSIGNATURES_SRC)

.PHONY: clean-signatures
clean-signatures::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/signatures

#
# other commands
#

# evt

EVT_SRC_DIRS = ./cmd/evt
EVT_SRC = $(shell find $(EVT_SRC_DIRS) \
			-type f \
			-name '*.go' \
			! -name '*_test.go' \
			)
EVT_TRIGGERS_DIR = $(EVT_SRC_DIRS)/cmd/trigger/triggers

.PHONY: evt
evt:: $(OUTPUT_DIR)/evt

$(OUTPUT_DIR)/evt:: \
	$(EVT_SRC) \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
#
	$(CMD_GO) build \
		-ldflags="$(GO_DEBUG_FLAG) \
			" \
		-v -o $@ \
		./cmd/evt
	cp -r $(EVT_TRIGGERS_DIR) $(OUTPUT_DIR)/evt-triggers


.PHONY: clean-evt
clean-evt::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/evt
	$(CMD_RM) -rf $(OUTPUT_DIR)/evt-triggers



# image builds drive the container engine: host/native only (the container
# context gets clear-error stubs instead - see the host-only guards below)
ifneq ($(TRACEE_RUN_CONTEXT),container)
.PHONY: evt-trigger-runner
evt-trigger-runner:
#
	$(MAKE) -f builder/Makefile.evt-trigger-runner build

.PHONY: clean-evt-trigger-runner
clean-evt-trigger-runner:
#
	$(MAKE) -f builder/Makefile.evt-trigger-runner clean
endif

# tracee-bench

TRACEE_BENCH_SRC_DIRS = ./cmd/tracee-bench/
TRACEE_BENCH_SRC = $(shell find $(TRACEE_BENCH_SRC_DIRS) \
			-type f \
			-name '*.go' \
			! -name '*_test.go' \
			)

.PHONY: tracee-bench
tracee-bench:: $(OUTPUT_DIR)/tracee-bench

$(OUTPUT_DIR)/tracee-bench:: \
	$(TRACEE_BENCH_SRC) \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(OUTPUT_DIR)
#
	$(CMD_GO) build \
		-v -o $@ \
		./cmd/tracee-bench

.PHONY: clean-tracee-bench
clean-tracee-bench::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-bench


#
#	traceectl 
#

SUBDIR_TRACEECTL = cmd/traceectl
SUBDIR_TRACEECTL_BINARY = $(SUBDIR_TRACEECTL)/dist/traceectl

TRACEECTL_SRC = $(shell find $(SUBDIR_TRACEECTL) \
		-type f \
		-name '*.go' \
		! -name '*_test.go' \
)


.PHONY: traceectl
traceectl:: $(OUTPUT_DIR)/traceectl

$(OUTPUT_DIR)/traceectl:: \
	$(TRACEECTL_SRC)
#
	$(MAKE) -C $(SUBDIR_TRACEECTL)
	$(CMD_MKDIR) -p $(dir $@)
	$(CMD_CP) $(SUBDIR_TRACEECTL_BINARY) $@

.PHONY: clean-traceectl
clean-traceectl::
	$(MAKE) -C $(SUBDIR_TRACEECTL) clean
	$(CMD_RM) -f $(OUTPUT_DIR)/traceectl


#
# unit tests
#

.PHONY: test-unit
test-unit:: \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF_CHECK) \
		-short \
		$(GO_TEST_RACE) \
		-shuffle on \
		-failfast \
		-v \
		-coverprofile=coverage.txt \
		-covermode=atomic \
		$(if $(TEST),-run '$(TEST)') \
		$(if $(PKG),./$(PKG)/...,./cmd/... ./pkg/... ./signatures/...)

.PHONY: test-types
test-types:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@# Note that we must change the directory here because types is a standalone Go module.
	@cd ./types && $(CMD_GO) test \
		-short \
		$(GO_TEST_RACE) \
		-shuffle on \
		-v \
		./...

.PHONY: test-common
test-common:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@# Note that we must change the directory here because common is a standalone Go module.
	@cd ./common && $(CMD_GO) test \
		-short \
		$(GO_TEST_RACE) \
		-shuffle on \
		-v \
		./...

# detectors, api and cmd/traceectl are standalone Go modules (own go.mod) with
# unit tests that test-unit's main-module run does not reach; test each in its
# own dir. Pure Go - no eBPF tags/CGO needed. (common-extended is handled just
# below - a skeleton here, populated by the private overlay.)
.PHONY: test-detectors
test-detectors:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@cd ./detectors && $(CMD_GO) test -short $(GO_TEST_RACE) -shuffle on -v ./...

.PHONY: test-api
test-api:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@cd ./api && $(CMD_GO) test -short $(GO_TEST_RACE) -shuffle on -v ./...

.PHONY: test-traceectl
test-traceectl:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@cd ./cmd/traceectl && $(CMD_GO) test -short $(GO_TEST_RACE) -shuffle on -v ./...

# common-extended is a module skeleton (no tests in the public repo); the
# private/extended overlay populates it. Wiring it in now means those tests run
# for free there, and it is a harmless no-op ("no test files") here.
.PHONY: test-common-extended
test-common-extended:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@cd ./common-extended && $(CMD_GO) test -short $(GO_TEST_RACE) -shuffle on -v ./...

#
# aggregate test suites
#

# Unit tests split into two groups:
#   1. the main module's internal packages (./cmd ./pkg ./signatures) -> test-unit
#   2. the standalone Go submodules maintained in this repo, each with its own
#      go.mod (types, common, detectors, api, traceectl, common-extended)
#      -> tests-submodules
# tests-unit runs both. All privilege-free. Run-all: a failing target does not
# stop the rest; the aggregate exit code is non-zero if any failed.
#
# The TESTS_* lists use += so the private overlay (Makefile.extended-pre/-post)
# can add its own suites/modules, e.g. `TESTS_SUBMODULES += test-secret-mod`;
# the loops expand them at run time. Targets are :: so an overlay may also
# append a recipe. Same pattern as HOST_ONLY_GOALS/PRIVILEGED_GOALS.
TESTS_SUBMODULES += test-types test-common test-detectors test-api test-traceectl \
	test-common-extended

.PHONY: tests-submodules
tests-submodules::
#
	@fail=0; \
	for t in $(TESTS_SUBMODULES); do \
		echo ""; \
		echo "======================= make $$t ======================="; \
		$(MAKE) $$t || { fail=1; echo "[tests-submodules] $$t FAILED"; }; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "[tests-submodules] one or more modules FAILED (see above)"; exit 1; fi; \
	echo "[tests-submodules] all submodules passed"

.PHONY: tests-unit
tests-unit::
#
	@fail=0; \
	for t in test-unit $(TESTS_SUBMODULES); do \
		echo ""; \
		echo "======================= make $$t ======================="; \
		$(MAKE) $$t || { fail=1; echo "[tests-unit] $$t FAILED"; }; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "[tests-unit] one or more unit suites FAILED (see above)"; exit 1; fi; \
	echo "[tests-unit] all unit tests passed"

# the E2E family in ONE run (core + net + kernel + the microVM tampering tests,
# last). Like `tests`, a single privileged goal -> ONE container, ONE sudo. Same
# run-all semantics. Routed through the ubuntu-fc image (see mk/dispatch.mk).
TESTS_E2E += test-e2e test-e2e-net test-e2e-kernel test-e2e-vm

.PHONY: tests-e2e
tests-e2e::
#
	@fail=0; \
	for t in $(TESTS_E2E); do \
		echo ""; \
		echo "======================= make $$t ======================="; \
		$(MAKE) $$t || { fail=1; echo "[tests-e2e] $$t FAILED"; }; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "[tests-e2e] one or more suites FAILED (see above)"; exit 1; fi; \
	echo "[tests-e2e] all e2e suites passed"

# EVERY test suite in ONE run. Because this is a single privileged make goal, it
# dispatches into ONE container (see mk/dispatch.mk: PRIVILEGED_GOALS + the fc
# image path) - so the engine escalates with sudo exactly ONCE and every suite
# then runs inside that one long-lived root container, no re-prompt. The
# kernel-tampering suite (test-e2e-vm) runs last, in the microVM. Run-all: a
# failing suite does not stop the others; the aggregate exit code is non-zero if
# any failed. (test-performance and test-upstream-libbpfgo are intentionally
# left out - a benchmark and a CI-only libbpfgo-swap variant; run them directly.)
TESTS_SUITES += tests-unit \
	test-integration \
	test-compatibility \
	test-e2e test-e2e-net test-e2e-kernel \
	test-e2e-vm

.PHONY: tests
tests::
#
	@fail=0; \
	for t in $(TESTS_SUITES); do \
		echo ""; \
		echo "======================= make $$t ======================="; \
		$(MAKE) $$t || { fail=1; echo "[tests] $$t FAILED"; }; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "[tests] one or more suites FAILED (see above)"; exit 1; fi; \
	echo "[tests] all suites passed"

SCRIPTS_TEST_DIR = scripts

.PHONY: run-scripts-test-unit
run-scripts-test-unit::
#
	@$(SCRIPTS_TEST_DIR)/run_test_scripts.sh

#
# coverage targets
#

.PHONY: coverage
coverage:: test-unit
#
	@echo "Unit test coverage:"
	@$(CMD_GO) tool cover -func=coverage.txt

.PHONY: coverage-html
coverage-html:: test-unit
#
	@echo "Generating HTML coverage report..."
	@$(CMD_GO) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

#
# integration tests
#

$(OUTPUT_DIR)/syscaller:: \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.check_$(CMD_GO) \
#
	$(MAKE) embedded-dirs
	$(MAKE) $(OUTPUT_DIR)/tracee.bpf.o
	$(GO_ENV_EBPF) \
	$(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-o $(OUTPUT_DIR)/syscaller ./tests/integration/syscaller/cmd

.PHONY: test-integration
test-integration:: \
	$(OUTPUT_DIR)/syscaller \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
# the run is teed into a log so a FAILED/SKIPPED leaf-test summary can be
# printed at the end; the real go test exit code is preserved past the pipe
	@LOG=$$(mktemp); RC_FILE=$$(mktemp); \
	( $(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-shuffle on \
		-timeout 20m \
		$(GO_TEST_RACE) \
		-v \
		-p 1 \
		-count=1 \
		-coverprofile=integration-coverage.txt \
		-covermode=atomic \
		$(if $(TEST),-run '$(TEST)') \
		./tests/integration/... ; \
	echo $$? > $${RC_FILE} ) 2>&1 | tee $${LOG}; \
	RC=$$(cat $${RC_FILE}); rm -f $${RC_FILE}; \
	LEAF_FAILS=$$(grep -E '^[[:space:]]*--- FAIL: ' $${LOG} | sed -E 's/^[[:space:]]*--- FAIL: //; s/ \([0-9.]+s\)$$//' | awk '{a[NR]=$$0} END{for(i=1;i<=NR;i++){p=0;for(j=1;j<=NR;j++)if(i!=j&&index(a[j],a[i]"/")==1){p=1;break}if(!p)print a[i]}}'); \
	LEAF_SKIPS=$$(grep -E '^[[:space:]]*--- SKIP: ' $${LOG} | sed -E 's/^[[:space:]]*--- SKIP: //; s/ \([0-9.]+s\)$$//' | awk '{a[NR]=$$0} END{for(i=1;i<=NR;i++){p=0;for(j=1;j<=NR;j++)if(i!=j&&index(a[j],a[i]"/")==1){p=1;break}if(!p)print a[i]}}'); \
	FAILS=$$(printf '%s' "$${LEAF_FAILS}" | grep -c . || true); \
	SKIPS=$$(printf '%s' "$${LEAF_SKIPS}" | grep -c . || true); \
	echo ""; \
	echo "================== integration test summary =================="; \
	if [ "$${FAILS}" != "0" ]; then \
		echo "FAILED ($${FAILS}):"; \
		printf '%s\n' "$${LEAF_FAILS}" | sed 's/^/    /'; \
	fi; \
	if [ "$${RC}" != "0" ] && [ "$${FAILS}" = "0" ]; then \
		echo "RUN FAILED (exit $${RC}) with no per-test FAIL line (crash/timeout/build error) - see output above"; \
	fi; \
	if [ "$${SKIPS}" != "0" ]; then \
		echo "SKIPPED ($${SKIPS}):"; \
		printf '%s\n' "$${LEAF_SKIPS}" | sed 's/^/    /'; \
	fi; \
	if [ "$${RC}" = "0" ] && [ "$${FAILS}" = "0" ] && [ "$${SKIPS}" = "0" ]; then \
		echo "all tests passed, no skips"; \
	fi; \
	echo "=============================================================="; \
	rm -f $${LOG}; \
	exit $${RC}


.PHONY: test-compatibility
test-compatibility:: \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@$(MAKE) embedded-dirs
	$(MAKE) $(OUTPUT_DIR)/tracee.bpf.o
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			-s=false -w=false \
			" \
		-shuffle on \
		-timeout 20m \
		$(GO_TEST_RACE) \
		-v \
		-p 1 \
		-count=1 \
		-coverprofile=compatibility-coverage.txt \
		-covermode=atomic \
		./tests/compatibility/...

.PHONY: test-upstream-libbpfgo
test-upstream-libbpfgo:: \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	./tests/libbpfgo.sh $(GO_ENV_EBPF)

#
# performance tests
#

.PHONY: test-performance
test-performance:: \
	| $(STAMPS_DIR)/.eval_goenv \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@$(MAKE) tracee
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		$(GO_TEST_RACE) \
		-shuffle on \
		-v \
		-p 1 \
		-count=1 \
		./tests/perftests/... \

#
# E2E tests
#

# E2E test arguments (e.g., make test-e2e E2E_ARGS="--keep-artifacts")
E2E_ARGS ?=

.PHONY: test-e2e
test-e2e:: \
	tracee-e2e \
	lsm-check
#
	@echo "Running E2E core tests..."
	@echo "Note: the kernel-module tests (FTRACE_HOOK, HOOKED_SYSCALL) self-skip"
	@echo "      here (no in-container kernel headers); run them with 'make test-e2e-vm'."
	./tests/e2e/run.sh $(E2E_ARGS)

.PHONY: test-e2e-net
test-e2e-net:: \
	tracee-e2e-net
#
	@echo "Running E2E network tests..."
	./tests/e2e/run-net.sh $(E2E_ARGS)

.PHONY: test-e2e-kernel
test-e2e-kernel:: \
	tracee
#
	@echo "Running E2E kernel tests..."
	./tests/e2e/run-kernel.sh $(E2E_ARGS)

# kernel-tampering core tests (build+insmod real .ko, read host dmesg) run in
# a throwaway Firecracker microVM instead of against the live kernel. Builds
# the same prerequisites as test-e2e; the runner assembles a rootfs from this
# (ubuntu-fc) environment and boots the HOST's running kernel. x86_64 only -
# the modules are x86-only, so skip cleanly elsewhere. INSTTESTS overrides the
# default two-test selection.
INSTTESTS ?=
.PHONY: test-e2e-vm
test-e2e-vm:: \
	tracee-e2e \
	lsm-check
#
	@if [ "$(UNAME_M)" != "x86_64" ]; then \
		echo "skip test-e2e-vm: kernel-module tests are x86_64-only (got $(UNAME_M))"; \
		exit 0; \
	fi
	@echo "Running kernel-tampering E2E tests in a Firecracker microVM..."
	$(if $(INSTTESTS),INSTTESTS='$(INSTTESTS)') ./scripts/e2e-firecracker.sh

#
# development
#

.PHONY: bear
bear:: \
	clean \
	$(LIBBPF_OBJ) \
	| $(STAMPS_DIR)/.check_$(CMD_BEAR)
#
	$(CMD_BEAR) -- $(MAKE) tracee

.PHONY: go-tidy
go-tidy:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@echo "Running go mod tidy on all workspace modules..."
	@# Process root module first
	@if [ -f "./go.mod" ]; then \
		echo "Tidying root module..."; \
		$(CMD_GO) mod tidy; \
	fi
	@# Then process all subdirectory modules
	@for mod_file in $$(find . -name "go.mod" -type f -not -path "./go.mod" $(foreach path,$(EXCLUDED_MODULES),-not -path "$(path)") | sort); do \
		mod_dir=$$(dirname "$$mod_file"); \
		echo "Tidying $$mod_dir..."; \
		(cd "$$mod_dir" && $(CMD_GO) mod tidy); \
	done
	@echo "Workspace maintenance complete!"

# Prevent make from treating package arguments as targets
ifneq ($(filter go-get,$(MAKECMDGOALS)),)
go-get-args := $(filter-out go-get,$(MAKECMDGOALS))
ifneq ($(strip $(go-get-args)),)
$(go-get-args):
	@:
endif
endif

.PHONY: go-get
go-get:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	@args="$(filter-out go-get,$(MAKECMDGOALS))"; \
	if [ -z "$$args" ]; then \
		echo "Usage: make go-get <package>[@version]..."; \
		exit 1; \
	fi; \
	echo "Running go get $$args on all workspace modules..."; \
	if [ -f "./go.mod" ]; then \
		echo "Getting in root module..."; \
		$(CMD_GO) get $$args; \
	fi; \
	for mod_file in $$(find . -name "go.mod" -type f -not -path "./go.mod" $(foreach path,$(EXCLUDED_MODULES),-not -path "$(path)") | sort); do \
		mod_dir=$$(dirname "$$mod_file"); \
		echo "Getting in $$mod_dir..."; \
		(cd "$$mod_dir" && $(CMD_GO) get $$args); \
	done; \
	echo "Workspace go get complete!"

# formatting and linting recipes (check-fmt, fix-fmt, check-lint, check-code)
include mk/checks.mk


.PHONY: check-vet
check-vet:: \
	| $(STAMPS_DIR)/.install_libbpf_headers \
	$(STAMPS_DIR)/.checkver_$(CMD_GO)
#
	$(GO_ENV_EBPF_CHECK) \
	$(CMD_GO) vet \
		-tags $(GO_TAGS_EBPF_CHECK) \
		./...

.PHONY: check-staticcheck
check-staticcheck:: \
	| $(STAMPS_DIR)/.install_libbpf_headers \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(STAMPS_DIR)/.check_$(CMD_STATICCHECK)
#
	$(GO_ENV_EBPF_CHECK) \
	$(CMD_STATICCHECK) -f stylish \
		-tags $(GO_TAGS_EBPF_CHECK) \
		./...

.PHONY: check-err
check-err:: \
	| $(STAMPS_DIR)/.install_libbpf_headers \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(STAMPS_DIR)/.check_$(CMD_ERRCHECK)
#
	$(GO_ENV_EBPF_CHECK) \
	$(CMD_ERRCHECK) \
		-tags $(GO_TAGS_EBPF_CHECK),static \
		-ignoretests \
		-ignore 'fmt:[FS]?[Pp]rint*|[wW]rite' \
		-ignore '[rR]ead|[wW]rite' \
		-ignore 'RegisterEventProcessor' \
		./...

.PHONY: check-vulncheck
check-vulncheck:: \
	| $(STAMPS_DIR)/.install_libbpf_headers \
	$(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(STAMPS_DIR)/.check_$(CMD_GOVULNCHECK)
#
	@echo ""
	@echo "--- [govulncheck] ./ (root module) ---"
	$(GO_ENV_EBPF_CHECK) \
	$(CMD_GOVULNCHECK) \
		-tags $(GO_TAGS_EBPF_CHECK) \
		./... \
	|| EXIT_CODE=$$?
	@for mod_file in $$(find . -name "go.mod" -type f -not -path "./go.mod" $(foreach path,$(EXCLUDED_MODULES),-not -path "$(path)") | sort); do \
		mod_dir=$$(dirname "$$mod_file"); \
		echo ""; \
		echo "--- [govulncheck] $$mod_dir ---"; \
		(cd "$$mod_dir" && $(CMD_GOVULNCHECK) ./...) || EXIT_CODE=$$?; \
	done
	@echo ""
	@if [ -z "$${EXIT_CODE}" ]; then \
		echo "govulncheck: all modules clean"; \
	else \
		echo "govulncheck: findings detected in one or more modules"; \
	fi
	@echo ""
	exit $${EXIT_CODE:-0}

#
# pull request verifier
#

.PHONY: format-pr
format-pr:: \
	| $(STAMPS_DIR)/.check_$(CMD_GIT)
#
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) $(CURDIR)/scripts/checkpatch.sh pr-format

.PHONY: check-pr
check-pr::
#	Enhanced to use comprehensive checkpatch script that includes:
#	- Code analysis (formatting, linting, static analysis, vulnerability scanning)
#	- Unit tests (Go and script tests)
#	- PR formatting
#	Examples:
#	  make check-pr                                # Check HEAD (default)
#	  make check-pr-fast                           # Quick checks only
#	  make check-pr-skip-docs                      # Skip documentation verification
#	  make check-pr-skip-tests                     # Skip unit tests
#	  make check-pr BASE_REF=v1.0.0                # Compare against v1.0.0
#	  make check-pr ARGS="--fast HEAD~1"           # Custom options + git ref
#	  BASE_REF=upstream/release make check-pr      # Set base ref via env
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh $(if $(ARGS),$(ARGS),HEAD)

# Convenience targets for common use cases
.PHONY: check-pr-fast
check-pr-fast::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --fast HEAD

.PHONY: check-pr-skip-docs
check-pr-skip-docs::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --skip-docs HEAD

.PHONY: check-pr-skip-tests
check-pr-skip-tests::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --skip-unit-tests HEAD

#
# tracee.proto
#

.PHONY: protoc
protoc::
#
	# Generate protos with JSON marshallers (excludes event.proto and event_data.proto with custom implementations)
	$(CMD_PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-json_out=orig_name=true,paths=source_relative:. \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(TRACEE_PROTOS)

	# Generate event.proto and event_data.proto WITHOUT JSON marshallers (have custom implementation)
	$(CMD_PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(TRACEE_PROTOS_NO_JSON)

#
# man pages
#

FLAGS_MARKDOWN_DIR ?= docs/docs/flags
EVENTS_MARKDOWN_DIR ?= docs/docs/events/builtin/man
MAN_DIR ?= docs/man
OUTPUT_MAN_DIR := $(OUTPUT_DIR)/$(MAN_DIR)
FLAGS_MARKDOWN_FILES := $(shell find $(FLAGS_MARKDOWN_DIR) \
					-type f \
					-name '*.md' \
				)
EVENTS_MARKDOWN_FILES := $(shell find $(EVENTS_MARKDOWN_DIR) \
					-type f \
					-name '*.md' \
				)
# Extract just the basename for event man files (e.g., builtin/extra/bpf_attach.md -> bpf_attach.1)
EVENTS_MAN_FILES := $(addprefix $(MAN_DIR)/,$(notdir $(patsubst %.md,%.1,$(EVENTS_MARKDOWN_FILES))))
MAN_FILES := $(patsubst $(FLAGS_MARKDOWN_DIR)/%.md,$(MAN_DIR)/%,$(FLAGS_MARKDOWN_FILES)) \
			 $(EVENTS_MAN_FILES)

# Define function to create a rule for each event man page
define EVENT_MAN_RULE
$(MAN_DIR)/$(notdir $(patsubst %.md,%.1,$(1))): $(1) \
	| $(STAMPS_DIR)/.check_$(CMD_PANDOC) \
	$(OUTPUT_MAN_DIR)
	@echo Generating event man page $$@ from $$< && \
	$(CMD_PANDOC) \
		--verbose \
		--standalone \
		--to man \
		$$< \
		-o $$@ && \
	echo Copying $$@ to $(OUTPUT_MAN_DIR) && \
	$(CMD_CP) $$@ $(OUTPUT_MAN_DIR)
endef

$(OUTPUT_MAN_DIR): \
	| $(STAMPS_DIR)/.check_$(CMD_MKDIR)
#
	$(CMD_MKDIR) -p $@

$(MAN_DIR)/%: $(FLAGS_MARKDOWN_DIR)/%.md \
	| $(STAMPS_DIR)/.check_$(CMD_PANDOC) \
	$(OUTPUT_MAN_DIR)
#
	@echo Generating flag man page $@ && \
	$(CMD_PANDOC) \
		--verbose \
		--standalone \
		--to man \
		$< \
		-o $@ && \
	echo Copying $@ to $(OUTPUT_MAN_DIR) && \
	$(CMD_CP) $@ $(OUTPUT_MAN_DIR)

# Generate specific rules for each event man page
$(foreach src,$(EVENTS_MARKDOWN_FILES),$(eval $(call EVENT_MAN_RULE,$(src))))

.PHONY: clean-man
clean-man::
	@echo Cleaning $(MAN_DIR) && \
	$(CMD_RM) -f $(MAN_DIR)/* && \
	echo Cleaning $(OUTPUT_MAN_DIR) && \
	$(CMD_RM) -rf $(OUTPUT_MAN_DIR)

.PHONY: man
man:: $(MAN_FILES)


#
# clean
#

.PHONY: clean
clean:: clean-lsm-check
#
	$(CMD_RM) -rf $(OUTPUT_DIR)
# legacy root-level state from before stamps moved under $(STAMPS_DIR)
	$(CMD_RM) -f goenv.mk
	$(CMD_RM) -f .*.md5
	$(CMD_RM) -f .build_*
	$(CMD_RM) -f .check*
	$(CMD_RM) -f .eval_*
	$(CMD_RM) -f .*-pkgs*

# tracee-operator

.PHONY: tracee-operator
tracee-operator:: $(OUTPUT_DIR)/tracee-operator

$(OUTPUT_DIR)/tracee-operator:: \
	| $(STAMPS_DIR)/.checkver_$(CMD_GO) \
	$(OUTPUT_DIR)
#
	$(CMD_GO) build \
		-v -o $@ \
		./cmd/tracee-operator

.PHONY: clean-tracee-operator
clean-tracee-operator::
#
	$(CMD_RM) -rf $(OUTPUT_DIR)/tracee-operator

# kubernetes operator

.PHONY: k8s-manifests
k8s-manifests:: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CMD_CONTROLLER_GEN) rbac:roleName=tracee crd webhook paths="./pkg/k8s/..." output:crd:artifacts:config=deploy/helm/tracee/crds output:rbac:artifacts:config=deploy/helm/tracee/templates/

.PHONY: k8s-generate
k8s-generate:: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CMD_CONTROLLER_GEN) object:headerFile="deploy/boilerplate.go.txt" paths="./pkg/k8s/..."

# benchmarks
.PHONY: bench-network
bench-network::
	./performance/benchmark/network/bench.sh $(IMAGE) $(OUTPUT) $(TIME)

# load extended-post Makefile, if exists
-include Makefile.extended-post

#
# host-only guards
#

# these targets drive the container engine, which exists only on the host;
# inside the build container they would fail with a confusing "No rule to
# make target" - stop them with a clear message instead
HOST_ONLY_STUBS := shell image images image-fc clean-images image-distro-test \
	stop-buildenv mkdocs-build mkdocs-serve \
	evt-trigger-runner clean-evt-trigger-runner \
	dev dev-stop dev-ssh attach clean-dev \
	lsp-go lsp-c lsp-print-go lsp-print-c

ifeq ($(TRACEE_RUN_CONTEXT),container)
.PHONY: $(HOST_ONLY_STUBS)
$(HOST_ONLY_STUBS):
	@echo "make: '$@' drives the container engine - run it on the host, not inside the build container" >&2
	@exit 1
endif
