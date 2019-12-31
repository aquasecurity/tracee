os ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

.PHONY: build
build: tracee_$(os)

SRC = $(shell find . -type f -name '*.go')
tracee_%: $(SRC)
	GOOS=$* go build -o $(@F)

.PHONY: clean
clean:
	rm tracee_*
