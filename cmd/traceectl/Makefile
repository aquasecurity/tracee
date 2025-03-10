
BINARY_NAME ?= traceectl
DIST_DIR ?= dist
VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS = -ldflags "-X main.version=$(VERSION)"


.PHONY: all 
all: build 

.PHONY: build
build:
	mkdir -p $(DIST_DIR)

	go build \
		$(LDFLAGS) \
		-o $(DIST_DIR)/$(BINARY_NAME) \
		main.go 

	@echo "Built $(BINARY_NAME)-$(GOOS)-$(GOARCH) in $(DIST_DIR)"

.PHONY: test
test:
	go test \
	-v \
	-cover \
	-race \
	./...


.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "  all: Builds the traceectl binary (default)."
	@echo "  build: Builds the traceectl binary."
	@echo "  test: Runs unit tests with coverage and race detection."
	@echo "  clean: Removes the build artifacts and the dist directory."
	@echo "  help: Displays this help message."
	@echo ""
	@echo "Variables:"
	@echo ""
	@echo "  BINARY_NAME: Name of the binary (default: traceectl)."
	@echo "  DIST_DIR: Directory for build artifacts (default: dist)."
	@echo "  VERSION: Version string (default: git describe --tags --always --dirty)."
