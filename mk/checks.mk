#
# Formatting and linting (absorbed from builder/Makefile.checkers).
#
# Runs in the buildenv container by default like every other target; the
# tools (clang-format 19, goimports-reviser, revive, ...) are baked into the
# image by scripts/installation/install-clang.sh / install-go-tools.sh.
#

CMD_FIND ?= find
# Try clang-format-19 first, then fall back to generic clang-format
CMD_CLANG_FMT ?= $(shell command -v clang-format-19 >/dev/null 2>&1 && echo clang-format-19 || echo clang-format)
CMD_GOFMT ?= gofmt
CMD_GOIMPORTS ?= goimports-reviser
CMD_REVIVE ?= revive

# eBPF C formatting requires exactly this clang-format major version
CLANG_FMT_REQUIRED_VERSION = 19

$(STAMPS_DIR)/.checkver_$(CMD_CLANG_FMT):
#
	@command -v $(CMD_CLANG_FMT) >/dev/null
	if [ $$? -ne 0 ]; then
		echo "ERROR: $(CMD_CLANG_FMT) not found. Please install clang-format version $(CLANG_FMT_REQUIRED_VERSION)"
		exit 1
	fi
	CLANG_FMT_VERSION=$$($(CMD_CLANG_FMT) --version 2>/dev/null | head -n1 | grep -o "clang-format version [0-9]*" | grep -o "[0-9]*" || echo "0")
	if [ "$${CLANG_FMT_VERSION}" != "$(CLANG_FMT_REQUIRED_VERSION)" ]; then
		echo "ERROR: $(CMD_CLANG_FMT) version $${CLANG_FMT_VERSION} found, but version $(CLANG_FMT_REQUIRED_VERSION) is required"
		exit 1
	else
		echo "Using $(CMD_CLANG_FMT) version $${CLANG_FMT_VERSION}"
		$(CMD_MKDIR) -p $(@D)
		touch $@ # avoid target rebuilds due to non-existing file
	fi

#
# check formatting (clang-format, goimports-reviser, gofmt)
#

C_FILES_TO_BE_CHECKED = $(shell find ./pkg/ebpf/c/ -regextype posix-extended -regex '.*\.(h|c)' | xargs)

CMD_GOIMPORTS_COMPANY_PREFIXES ?= "github.com/aquasecurity"
CMD_GOIMPORTS_PROJECT ?= "github.com/aquasecurity/tracee"
CMD_GOIMPORTS_OUTPUT_FILE ?= $(STAMPS_DIR)/.check-goimports-fmt

.PHONY: check-fmt
check-fmt:: | \
	$(STAMPS_DIR)/.checkver_$(CMD_CLANG_FMT) \
	$(STAMPS_DIR)/.check_$(CMD_FIND) \
	$(STAMPS_DIR)/.check_$(CMD_GOIMPORTS) \
	$(STAMPS_DIR)/.check_$(CMD_GOFMT)
#
	@$(CMD_MKDIR) -p $(STAMPS_DIR)
	errors=0
	echo "Checking C and eBPF files and headers formatting..."
	$(CMD_CLANG_FMT) --dry-run $(C_FILES_TO_BE_CHECKED) > $(STAMPS_DIR)/.check-c-fmt 2>&1
	clangfmtamount=$$(cat $(STAMPS_DIR)/.check-c-fmt | wc -l)
	if [ $${clangfmtamount} -ne 0 ]; then
		cat $(STAMPS_DIR)/.check-c-fmt
		errors=1
	fi
	rm -f $(STAMPS_DIR)/.check-c-fmt
#
	echo "Checking golang files imports formatting..."
	rm -f $(CMD_GOIMPORTS_OUTPUT_FILE)
	$(CMD_GOIMPORTS) \
		-output stdout \
		-list-diff \
		-company-prefixes $(CMD_GOIMPORTS_COMPANY_PREFIXES) \
		-project-name $(CMD_GOIMPORTS_PROJECT) \
		-excludes "3rdparty" \
		./... 2>/dev/null > $(CMD_GOIMPORTS_OUTPUT_FILE)
	goimportsamount=$$(grep -cve '^\s*$$' $(CMD_GOIMPORTS_OUTPUT_FILE))
	if [ $${goimportsamount} -ne 0 ]; then
		errors=1
	fi
	if [ $${errors} -ne 0 ]; then
		cat $(CMD_GOIMPORTS_OUTPUT_FILE)
		echo
		echo "Please fix formatting errors in the files above!"
		echo "Use: make fix-fmt"
		echo
		exit 1
	fi
#
	echo "Checking golang files formatting..."
	$(CMD_GOFMT) -l -s -d $$(find . -name '*.go' -not -path './3rdparty/*') | tee $(STAMPS_DIR)/.check-go-fmt
	gofmtamount=$$(cat $(STAMPS_DIR)/.check-go-fmt | wc -l)
	if [ $${gofmtamount} -ne 0 ]; then
		errors=1
	fi
	if [ $${errors} -ne 0 ]; then
		echo
		echo "Please fix formatting errors above!"
		echo "Use: make fix-fmt"
		echo
		exit 1
	fi
	rm -f $(STAMPS_DIR)/.check-go-fmt

#
# fix formatting (clang-format, goimports-reviser, gofmt)
#

.PHONY: fix-fmt
fix-fmt:: | \
	$(STAMPS_DIR)/.checkver_$(CMD_CLANG_FMT) \
	$(STAMPS_DIR)/.check_$(CMD_GOIMPORTS) \
	$(STAMPS_DIR)/.check_$(CMD_GOFMT)
#
	@echo "Fixing C and eBPF files and headers formatting..."
	$(CMD_CLANG_FMT) -i --verbose $(C_FILES_TO_BE_CHECKED)
#
	echo "Fixing golang files imports formatting..."
	$(CMD_GOIMPORTS) \
		-company-prefixes $(CMD_GOIMPORTS_COMPANY_PREFIXES) \
		-project-name $(CMD_GOIMPORTS_PROJECT) \
		-excludes "3rdparty" \
		./... 2>/dev/null
#
	echo "Fixing golang files formatting..."
	$(CMD_GOFMT) -l -s -w $$(find . -name '*.go' -not -path './3rdparty/*')

#
# golang linting (revive)
#

.PHONY: check-lint
check-lint:: | \
	$(STAMPS_DIR)/.check_$(CMD_REVIVE)
#
	@echo "Linting golang code..."
	$(CMD_REVIVE) -config .revive.toml -exclude 3rdparty/... ./...

#
# check code (go vet, static checkers, errcheck, govulncheck)
#
# The checks compile with the ebpfstub tag (see GO_TAGS_EBPF_CHECK), so they
# need no artifacts in dist/ and are safe to run concurrently; the sub-makes
# stay sequential only to keep tool output readable.
#

.PHONY: check-code
check-code::
#
	@set -e
	echo "Checking Golang vet..."
	MAKEFLAGS="-j1 --no-print-directory" $(MAKE) check-vet
	echo "Checking Golang with StaticChecker..."
	MAKEFLAGS="-j1 --no-print-directory" $(MAKE) check-staticcheck
	echo "Checking Golang with errcheck..."
	MAKEFLAGS="-j1 --no-print-directory" $(MAKE) check-err
	echo "Checking Golang with govulncheck..."
	MAKEFLAGS="-j1 --no-print-directory" $(MAKE) check-vulncheck
