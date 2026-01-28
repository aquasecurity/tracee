.PHONY: all | env
all:: signatures tracee evt traceectl lsm-check

#
# make
#

.ONESHELL:
SHELL = /bin/sh

BUILD_TYPE_FLAG := COMMON_BUILD
GO_TAGS_EBPF := core,ebpf,lsmsupport

EXCLUDED_MODULES := ./3rdparty/*

# load extended-pre Makefile, if exists
-include Makefile.extended-pre

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
MAKE = make
MAKEFLAGS += --no-print-directory

#
# env
#

GOENV_MK = goenv.mk

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

.check_%:
#
	@command -v $* >/dev/null
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

.checklib_%: \
	| .check_$(CMD_PKGCONFIG)
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
	} && touch $@ # avoid target rebuilds due to non-existing file

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

.checkver_$(CMD_CLANG):: \
	| .check_$(CMD_CLANG)
#
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	touch $@ # avoid target rebuilds over and over due to non-existing file

GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

.checkver_$(CMD_GO):: \
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
# usage
#

.PHONY: help
help::
	@echo ""
	@echo "# environment"
	@echo ""
	@echo "    $$ make env                      # show makefile environment/variables"
	@echo ""
	@echo "# build"
	@echo ""
	@echo "    $$ make all                      # build tracee, signatures & other tools"
	@echo "    $$ make bpf                      # build ./dist/tracee.bpf.o"
	@echo "    $$ make tracee                   # build ./dist/tracee"
	@echo "    $$ make tracee-bench             # build ./dist/tracee-bench"
	@echo "    $$ make signatures               # build ./dist/signatures"
	@echo "    $$ make tracee-e2e               # build ./dist/tracee-e2e (with e2e detectors)"
	@echo "    $$ make tracee-e2e-net           # build ./dist/tracee-e2e-net (with network e2e detectors)"
	@echo "    $$ make tracee-operator          # build ./dist/tracee-operator"
	@echo "    $$ make lsm-check                # build ./dist/lsm-check"
	@echo ""
	@echo "# clean"
	@echo ""
	@echo "    $$ make clean                    # wipe ./dist/"
	@echo "    $$ make clean-bpf                # wipe ./dist/tracee.bpf.o"
	@echo "    $$ make clean-tracee             # wipe ./dist/tracee"
	@echo "    $$ make clean-tracee-bench       # wipe ./dist/tracee-bench"
	@echo "    $$ make clean-signatures         # wipe ./dist/signatures"
	@echo "    $$ make clean-tracee-operator    # wipe ./dist/tracee-operator"
	@echo "    $$ make clean-lsm-check          # wipe ./dist/lsm-check"
	@echo ""
	@echo "# test"
	@echo ""
	@echo "    $$ make test-unit                # run all unit tests"
	@echo "    $$ make test-unit PKG=pkg/path   # run tests for specific package" 
	@echo "    $$ make test-unit TEST=TestName  # run specific test in all packages"
	@echo "    $$ make test-unit PKG=pkg/path TEST=TestName  # run specific test in specific package"
	@echo "    $$ make test-types               # run unit tests for types module"
	@echo "    $$ make test-common              # run unit tests for common module"
	@echo "    $$ make test-integration         # run integration tests"
	@echo "    $$ make test-compatibility       # run compatibility and fallback feature tests"
	@echo "    $$ make test-e2e                 # run E2E core tests (requires root)"
	@echo "    $$ make test-e2e-net             # run E2E network tests (requires root)"
	@echo "    $$ make test-e2e-kernel          # run E2E kernel tests (requires root)"
	@echo "    $$ make test-e2e E2E_ARGS='--keep-artifacts'  # pass flags to E2E scripts"
	@echo ""
	@echo "# development"
	@echo ""
	@echo "    $$ make bear                     # generate compile_commands.json"
	@echo "    $$ make check-pr                 # comprehensive PR checks (code, tests)"
	@echo "    $$ make check-pr-fast            # quick PR checks (skip static analysis + unit tests)"
	@echo "    $$ make check-pr-skip-tests      # PR checks without unit tests"
	@echo "    $$ make format-pr                # print formatted text for PR"
	@echo "    $$ make fix-fmt                  # fix formatting"
	@echo ""
	@echo "# performance testing"
	@echo ""
	@echo "    $$ make evt                      # build evt binary for stress testing"
	@echo "    $$ make evt-trigger-runner       # build container image for evt stress"
	@echo "    $$ EVT_TRIGGER_RUNNER_IMAGE=my-runner:dev make evt-trigger-runner  # custom image"
	@echo "    $$ make clean-evt-trigger-runner # clean evt trigger runner container"
	@echo ""
	@echo "# flags"
	@echo ""
	@echo "    $$ STATIC=1 make ...             # build static binaries"
	@echo "    $$ BTFHUB=1 STATIC=1 make ...    # build static binaries, embed BTF"
	@echo "    $$ DEBUG=1 make ...              # build binaries with debug symbols"
	@echo "    $$ METRICS=1 make ...            # build enabling BPF metrics"
	@echo "    $$ FIPS=1 make ...               # build FIPS 140-3 compliant binaries"
	@echo ""

#
# variables
#

BPF_VCPU = v2

#
# output dir
#

OUTPUT_DIR = ./dist

$(OUTPUT_DIR)::
#
	@$(CMD_MKDIR) -p $@
	$(CMD_MKDIR) -p $@/libbpf
	$(CMD_MKDIR) -p $@/libbpf/obj


#
# embedded directories required by different targets
#

.PHONY: embedded-dirs
embedded-dirs:: $(OUTPUT_DIR)/btfhub $(OUTPUT_DIR)/lsm_support

#
# dummy BPF object helpers (for tests that don't need real BPF)
#

# Creates a dummy BPF object if one doesn't exist
# Sets DUMMY_BPF_CREATED=1 in environment if dummy was created
# NOTE: Do NOT use this in parallel make calls.
define setup_dummy_bpf
if [ ! -f $(OUTPUT_DIR)/tracee.bpf.o ]; then \
	echo "[$(1)] Creating dummy BPF object..."; \
	$(CMD_MKDIR) -p $(OUTPUT_DIR); \
	$(CMD_TOUCH) $(OUTPUT_DIR)/tracee.bpf.o; \
	echo "DUMMY_BPF_CREATED=1" > $(OUTPUT_DIR)/.dummy-bpf-flag; \
else \
	echo "[$(1)] Using existing BPF object..."; \
	echo "DUMMY_BPF_CREATED=0" > $(OUTPUT_DIR)/.dummy-bpf-flag; \
fi
endef

# Removes dummy BPF object if it was created by setup_dummy_bpf
define cleanup_dummy_bpf
if [ -f $(OUTPUT_DIR)/.dummy-bpf-flag ]; then \
	DUMMY_BPF_CREATED=$$(cat $(OUTPUT_DIR)/.dummy-bpf-flag | cut -d'=' -f2); \
	if [ "$$DUMMY_BPF_CREATED" = "1" ]; then \
		echo "[$(1)] Removing dummy BPF object..."; \
		$(CMD_RM) -f $(OUTPUT_DIR)/tracee.bpf.o; \
	fi; \
	$(CMD_RM) -f $(OUTPUT_DIR)/.dummy-bpf-flag; \
fi
endef

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
LIBBPF_DESTDIR = $(OUTPUT_DIR)/libbpf
LIBBPF_OBJDIR = $(LIBBPF_DESTDIR)/obj
LIBBPF_OBJ = $(LIBBPF_OBJDIR)/libbpf.a

$(LIBBPF_OBJ):: .build_libbpf .build_libbpf_fix

.build_libbpf:: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \
	| .checkver_$(CMD_CLANG)
#
	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		PREFIX=$(abspath $(OUTPUT_DIR)) \
		DESTDIR=$(abspath $(LIBBPF_DESTDIR)) \
		OBJDIR=$(abspath $(LIBBPF_OBJDIR)) \
		LIBDIR=/to-be-removed \
		INCLUDEDIR=/include \
		UAPIDIR=/include \
		install install_uapi_headers
	@$(CMD_TOUCH) $@


LIBBPF_INCLUDE_UAPI = ./3rdparty/libbpf/include/uapi/linux

.build_libbpf_fix:: .build_libbpf
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


TRACEE_EBPF_CFLAGS = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(CMD_PKGCONFIG) $(PKG_CONFIG_FLAG) --cflags $(LIB_BPF))

.eval_goenv:: $(LIBBPF_OBJ)
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
		echo 'GO_ENV_EBPF := $(GO_ENV_EBPF)' > $(GOENV_MK)
		$(CMD_TOUCH) $@
	}

$(LIBBPF_SRC):: \
	| .check_$(CMD_GIT)
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
	| .eval_goenv \
	.checkver_$(CMD_GO) \
	.checklib_$(LIB_BPF)
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
btfhub:: .tracee.bpf.o.md5

.tracee.bpf.o.md5: \
	$(OUTPUT_DIR)/tracee.bpf.o \
	| .check_$(CMD_MD5)
#
ifeq ($(BTFHUB), 1)
	@input="$<"; \
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
	.eval_goenv \
	.checkver_$(CMD_GO) \
	.checklib_$(LIB_BPF) \
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
	| .eval_goenv \
	.checkver_$(CMD_GO)
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
	| .eval_goenv \
	.checkver_$(CMD_GO) \
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



.PHONY: evt-trigger-runner
evt-trigger-runner:
#
	$(MAKE) -f builder/Makefile.evt-trigger-runner build

.PHONY: clean-evt-trigger-runner
clean-evt-trigger-runner:
#
	$(MAKE) -f builder/Makefile.evt-trigger-runner clean

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
	| .checkver_$(CMD_GO) \
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
	$(if $(or $(PKG),$(TEST)),,test-types test-common) \
	| .eval_goenv \
	.checkver_$(CMD_GO)
#
	@$(MAKE) embedded-dirs
	@$(call setup_dummy_bpf,$@)
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-short \
		-race \
		-shuffle on \
		-failfast \
		-v \
		-coverprofile=coverage.txt \
		-covermode=atomic \
		$(if $(TEST),-run $(TEST)) \
		$(if $(PKG),./$(PKG)/...,./cmd/... ./pkg/... ./signatures/...) \
	|| EXIT_CODE=$$?
	$(call cleanup_dummy_bpf,$@)
	exit $${EXIT_CODE:-0}

.PHONY: test-types
test-types:: \
	| .checkver_$(CMD_GO)
#
	@# Note that we must change the directory here because types is a standalone Go module.
	@cd ./types && $(CMD_GO) test \
		-short \
		-race \
		-shuffle on \
		-v \
		./...

.PHONY: test-common
test-common:: \
	| .checkver_$(CMD_GO)
#
	@# Note that we must change the directory here because common is a standalone Go module.
	@cd ./common && $(CMD_GO) test \
		-short \
		-race \
		-shuffle on \
		-v \
		./...

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
	| .eval_goenv \
	.check_$(CMD_GO) \
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
	| .eval_goenv \
	.checkver_$(CMD_GO)
#
	@$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-shuffle on \
		-timeout 20m \
		-race \
		-v \
		-p 1 \
		-count=1 \
		-coverprofile=integration-coverage.txt \
		-covermode=atomic \
		$(if $(TEST),-run $(TEST)) \
		./tests/integration/...


.PHONY: test-compatibility
test-compatibility:: \
	| .eval_goenv \
	.checkver_$(CMD_GO)
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
		-race \
		-v \
		-p 1 \
		-count=1 \
		-coverprofile=compatibility-coverage.txt \
		-covermode=atomic \
		./tests/compatibility/...

.PHONY: test-upstream-libbpfgo
test-upstream-libbpfgo:: \
	| .eval_goenv \
	.checkver_$(CMD_GO)
#
	./tests/libbpfgo.sh $(GO_ENV_EBPF)

#
# performance tests
#

.PHONY: test-performance
test-performance:: \
	| .eval_goenv \
	.checkver_$(CMD_GO)
#
	@$(MAKE) tracee
	$(GO_ENV_EBPF) \
	$(CMD_GO) test \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-race \
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

#
# development
#

.PHONY: bear
bear:: \
	clean \
	$(LIBBPF_OBJ) \
	| .check_$(CMD_BEAR)
#
	$(CMD_BEAR) -- $(MAKE) tracee

.PHONY: go-tidy
go-tidy:: \
	| .checkver_$(CMD_GO)
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
check-code::
#
	@$(MAKE) -f builder/Makefile.checkers code-check


.PHONY: check-vet
check-vet:: \
	| .eval_goenv \
	.checkver_$(CMD_GO) \
	.checklib_$(LIB_BPF)
#
	@$(MAKE) embedded-dirs
	$(call setup_dummy_bpf,$@)
	$(GO_ENV_EBPF) \
	$(CMD_GO) vet \
		-tags $(GO_TAGS_EBPF) \
		./... \
	|| EXIT_CODE=$$?
	$(call cleanup_dummy_bpf,$@)
	exit $${EXIT_CODE:-0}

.PHONY: check-staticcheck
check-staticcheck:: \
	| .eval_goenv \
	.checkver_$(CMD_GO) \
	.checklib_$(LIB_BPF) \
	.check_$(CMD_STATICCHECK)
#
	@$(MAKE) embedded-dirs
	$(call setup_dummy_bpf,$@)
	$(GO_ENV_EBPF) \
	$(CMD_STATICCHECK) -f stylish \
		-tags $(GO_TAGS_EBPF) \
		./... \
	|| EXIT_CODE=$$?
	$(call cleanup_dummy_bpf,$@)
	exit $${EXIT_CODE:-0}

.PHONY: check-err
check-err:: \
	| .eval_goenv \
	.checkver_$(CMD_GO) \
	.checklib_$(LIB_BPF) \
	.check_$(CMD_ERRCHECK)
#
	@$(MAKE) embedded-dirs
	$(call setup_dummy_bpf,$@)
	$(GO_ENV_EBPF) \
	$(CMD_ERRCHECK) \
		-tags $(GO_TAGS_EBPF),static \
		-ignoretests \
		-ignore 'fmt:[FS]?[Pp]rint*|[wW]rite' \
		-ignore '[rR]ead|[wW]rite' \
		-ignore 'RegisterEventProcessor' \
		./... \
	|| EXIT_CODE=$$?
	$(call cleanup_dummy_bpf,$@)
	exit $${EXIT_CODE:-0}

#
# pull request verifier
#

LOGFROM ?= main

.PHONY: format-pr
format-pr:: \
	| .check_$(CMD_GIT)
#
	@$(CURDIR)/scripts/checkpatch.sh pr-format

.PHONY: check-pr
check-pr::
#	Enhanced to use comprehensive checkpatch script that includes:
#	- Code analysis (formatting, linting, static analysis)
#	- Unit tests (Go and script tests)
#	- PR formatting
#	Examples:
#	  make check-pr                                # Check HEAD (default)
#	  make check-pr-fast                           # Quick checks only
#	  make check-pr-skip-docs                      # Skip documentation verification
#	  make check-pr-skip-tests                     # Skip unit tests
#	  make check-pr BASE_REF=v1.0.0                # Compare against v1.0.0
#	  make check-pr ARGS="--fast HEAD~1"           # Custom options + git ref
#	  BASE_REF=origin/release make check-pr        # Set base ref via env
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh $(if $(ARGS),$(ARGS),HEAD)

# Convenience targets for common use cases
.PHONY: check-pr-fast
check-pr-fast::
	@./scripts/checkpatch.sh --fast HEAD

.PHONY: check-pr-skip-docs
check-pr-skip-docs::
	@./scripts/checkpatch.sh --skip-docs HEAD

.PHONY: check-pr-skip-tests
check-pr-skip-tests::
	@./scripts/checkpatch.sh --skip-unit-tests HEAD

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
	| .check_$(CMD_PANDOC) \
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
	| .check_$(CMD_MKDIR)
#
	$(CMD_MKDIR) -p $@

$(MAN_DIR)/%: $(FLAGS_MARKDOWN_DIR)/%.md \
	| .check_$(CMD_PANDOC) \
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
	$(CMD_RM) -f $(GOENV_MK)
	$(CMD_RM) -f .*.md5
	$(CMD_RM) -f .build_*
	$(CMD_RM) -f .check*
	$(CMD_RM) -f .eval_*
	$(CMD_RM) -f .*-pkgs*

# tracee-operator

.PHONY: tracee-operator
tracee-operator:: $(OUTPUT_DIR)/tracee-operator

$(OUTPUT_DIR)/tracee-operator:: \
	| .checkver_$(CMD_GO) \
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
