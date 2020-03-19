os ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

.PHONY: build
build: tracee_$(os)

SRC = $(shell find . -type f -name '*.go')
tracee_%: $(SRC)
	GOOS=$* go build -o $(@F)

.PHONY: test
test: $(SRC)
	go test -v ./...

.PHONY: clean
clean:
	rm tracee_*

python-test:
	python -m unittest -v test_container_tracer
