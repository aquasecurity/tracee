SRC = $(shell find . -type f -name '*.go' ! -name '*_test.go' )

.PHONY: build
build: dist/sigengine

dist/sigengine: $(SRC)
	GOOS=linux go build -v -o dist/sigengine

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf dist || true

