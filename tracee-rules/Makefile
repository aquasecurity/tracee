.PHONY: all
all: build rules

OUT_DIR ?= dist
OUT_BIN := $(OUT_DIR)/tracee-rules
OUT_RULES := $(OUT_DIR)/rules
GO_SRC := $(shell find . -type f -name '*.go')
GOSIGNATURES_DIR ?= signatures/golang
GOSIGNATURES_SRC := $(shell find $(GOSIGNATURES_DIR) -type f -name '*.go' ! -name '*_test.go' ! -path '$(GOSIGNATURES_DIR)/examples/*')
OUT_GOSIGNATURES := $(OUT_RULES)/builtin.so
REGO_SIGNATURES_DIR ?= signatures/rego
REGO_SIGNATURES_SRC := $(shell find $(REGO_SIGNATURES_DIR) -type f -name '*.rego' ! -name '*_test.rego' ! -path '$(REGO_SIGNATURES_DIR)/examples/*')

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BIN)

$(OUT_BIN): $(filter-out *_test.go,$(GO_SRC)) | $(OUT_DIR)
	go build -o $(OUT_BIN)

.PHONY: rules
rules: $(OUT_RULES)

$(OUT_RULES): $(GOSIGNATURES_DIR) $(REGO_SIGNATURES_SRC) | $(OUT_DIR)
	mkdir -p $(OUT_RULES)
	go build -buildmode=plugin -o $(OUT_GOSIGNATURES) $(GOSIGNATURES_SRC)
	cp $(REGO_SIGNATURES_SRC) $(OUT_RULES)
	
.PHONY: test
test: $(GO_SRC)
	go test -v ./...

.PHONY: clean mostlyclean
clean mostlyclean:
	-rm -rf $(OUT_DIR)
