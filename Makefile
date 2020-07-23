SRC = $(shell find . -type f -name '*.go' ! -name '*_test.go' )
ebpfProgramBase64 = $(shell base64 -w 0 tracee/event_monitor_ebpf.c)

.PHONY: build
build: dist/tracee

.PHONY: build-docker
build-docker: clean
	img=$$(docker build --target builder -q  .) && \
	cnt=$$(docker create $$img) && \
	docker cp $$cnt:/tracee/dist - | tar -xf - ; \
	docker rm $$cnt ; docker rmi $$img

dist/tracee: $(SRC) tracee/event_monitor_ebpf.c
	GOOS=linux go build -v -o dist/tracee -ldflags "-X github.com/aquasecurity/tracee/tracee.ebpfProgramBase64Injected=$(ebpfProgramBase64)"

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf dist || true

imageName ?= tracee
.PHONY: docker
docker:
	docker build -t $(imageName) .

.PHONY: release
# release by default will not publish. run with `publish=1` to publish
goreleaserFlags = --skip-publish --snapshot
ifdef publish
	goreleaserFlags =
endif
release:
	EBPFPROGRAM_BASE64=$(ebpfProgramBase64) goreleaser release --rm-dist $(goreleaserFlags)
