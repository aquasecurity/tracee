.PHONY: all
all: build plugins

OUT_DIR ?= dist
OUT_BIN := $(OUT_DIR)/tracee-rules
GO_SRC := $(shell find . -type f -name '*.go')
PLUGINS_DIR ?= signatures/golang
PLUGINS_SRC := $(shell find $(PLUGINS_DIR) -type f -name '*.go')
OUT_PLUGINS := $(OUT_DIR)/rules/builtin.so

.PHONY: build
build: $(filter-out *_test.go,$(GO_SRC))
	go build -o $(OUT_BIN)

plugins: $(PLUGINS_DIR)
	go build -buildmode=plugin -o $(OUT_PLUGINS) $(PLUGINS_SRC)
	
.PHONY: test
test: $(GO_SRC)
	cd $(PLUGINS_DIR) && go test -v

.PHONY: clean
clean:
	-rm -rf $(OUT_DIR)