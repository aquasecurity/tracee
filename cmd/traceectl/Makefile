.PHONY: all
all: traceectl

#
# make
#

.ONESHELL:
SHELL = /bin/sh

MAKEFLAGS += --no-print-directory

#
# tools
#

CMD_GO ?= go
CMD_MKDIR ?= mkdir
CMD_RM ?= rm

#
# traceectl binary
#

BINARY_NAME ?= traceectl
DIST_DIR ?= dist
VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

GO_SOURCES := $(shell find . -type f -name '*.go')
MODULE_FILES := $(addprefix $(CURDIR)/,go.mod go.sum)
BINARY_PATH := $(DIST_DIR)/$(BINARY_NAME)

$(DIST_DIR):
	$(CMD_MKDIR) -p $@

.PHONY: traceectl
traceectl: $(BINARY_PATH)

$(BINARY_PATH): \
	$(GO_SOURCES) \
	$(MODULE_FILES) \
	| $(DIST_DIR)
#
	$(CMD_GO) build \
		$(LDFLAGS) \
		-o $@ \
		.

.PHONY: test
test:
	$(CMD_GO) test \
	-v \
	-cover \
	-race \
	./...

.PHONY: clean
clean:
	$(CMD_RM) -rf $(DIST_DIR)

.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "  all: Builds the traceectl binary (default)."
	@echo "  traceectl: Builds the traceectl binary."
	@echo "  test: Runs unit tests with coverage and race detection."
	@echo "  clean: Removes the build artifacts and the dist directory."
	@echo "  help: Displays this help message."
	@echo ""
	@echo "Variables:"
	@echo ""
	@echo "  BINARY_NAME: Name of the binary (default: traceectl)."
	@echo "  DIST_DIR: Directory for build artifacts (default: dist)."
	@echo "  VERSION: Version string (default: git describe --tags --always --dirty)."
