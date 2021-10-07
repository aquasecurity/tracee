OUT_DIR ?= dist
OUT_DOCKER ?= tracee
OUT_ARCHIVE := $(OUT_DIR)/tracee.tar.gz
OUT_CHECKSUMS := $(OUT_DIR)/checksums.txt
PUSH_DOCKER_REPO ?= aquasec/tracee
PUSH_DOCKER_TAG ?= $(RELEASE_TAG:v%=%)
RELEASE_FILES := LICENSE $(OUT_DIR)/tracee-ebpf $(OUT_DIR)/tracee-rules $(OUT_DIR)/rules
# RELEASE_TAG must be set for the release target
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags 2>/dev/null || echo '0'))
BUILD_DATE = $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VCS_REF="$(shell git rev-parse --short HEAD)"
VCS_BRANCH="$(shell git rev-parse --abbrev-ref HEAD)"
BUILD_ARG_DOCKER =--build-arg VERSION=$(VERSION) --build-arg BUILD_DATE=$(BUILD_DATE) --build-arg VCS_BRANCH=$(VCS_BRANCH) --build-arg VCS_REF=$(VCS_REF)
MODULE_TAG_NAMES = tracee-ebpf/$(RELEASE_TAG) tracee-ebpf/external/$(RELEASE_TAG) tracee-rules/$(RELEASE_TAG)

CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_CHECKSUM ?= sha256sum
CMD_GITHUB ?= gh
CMD_TAR ?= tar
CMD_CP ?= cp
CMD_BATS ?= bats

release_tools := $(CMD_DOCKER) $(CMD_GIT) $(CMD_CHECKSUM) $(CMD_GITHUB) $(CMD_TAR) $(CMP_CP)

# DOCKER variable is used by sub-makefiles to build their artifact in a container
export DOCKER

.PHONY: all
all: $(RELEASE_FILES)

$(OUT_DIR):
	mkdir -p $@

# make_artifact invokes another make from $1 to make the artifact $2 using additional flags $3
define make_artifact
	$(MAKE) -C $1 mostlyclean dist/$2 $3 OUT_DIR=dist && $(CMD_CP) -r $1/dist/$2 $(OUT_DIR)
endef

$(OUT_DIR)/tracee-ebpf: tracee-ebpf | $(OUT_DIR)
	$(call make_artifact,$<,$(notdir $@))

$(OUT_DIR)/tracee-rules $(OUT_DIR)/rules: tracee-rules | $(OUT_DIR)
	$(call make_artifact,$<,$(notdir $@))

$(OUT_DIR)/tracee.bpf.%.o: bpf ;

.PHONY: bpf
bpf: tracee-ebpf | $(OUT_DIR)
		$(MAKE) -C $< mostlyclean $@ OUT_DIR=dist && $(CMD_CP) $</dist/tracee.bpf.*.o $(OUT_DIR)

# Use Gnu Make 4.3 "grouped targets" to make both $(OUT_ARCHIVE)
# and $(OUT_CHECKSUMS) with one command.
$(OUT_ARCHIVE) $(OUT_CHECKSUMS) &: $(RELEASE_FILES) | $(OUT_DIR)
	$(CMD_TAR) -czf $(OUT_ARCHIVE) $(RELEASE_FILES)
	$(CMD_CHECKSUM) $(OUT_ARCHIVE) > $(OUT_CHECKSUMS)

.PHONY: docker
docker:
	$(CMD_DOCKER) build $(BUILD_ARG_DOCKER) -t $(OUT_DOCKER):latest .

.PHONY: docker-slim
docker-slim:
	$(CMD_DOCKER) build $(BUILD_ARG_DOCKER) -t $(OUT_DOCKER):slim --build-arg BASE=slim .

# release_docker_image accepts a docker image $1, pushes it as $2 to remote repository, and records it in the release notes
define release_docker_image
	$(CMD_DOCKER) tag $(1) $(2) && $(CMD_DOCKER) push $(2) && echo '- `docker pull docker.io/$(2)`' >> $(release_notes);
endef

release_images_fat := $(PUSH_DOCKER_REPO):latest $(PUSH_DOCKER_REPO):$(PUSH_DOCKER_TAG)
release_images_slim := $(PUSH_DOCKER_REPO):slim $(PUSH_DOCKER_REPO):slim-$(PUSH_DOCKER_TAG)

.PHONY: release
release:
	test -n '$(RELEASE_TAG)' || (echo "missing required variable RELEASE_TAG" ; false)
	set -e; for tool in "$(release_tools)"; do command -v $$tool >/dev/null || (echo "missing required tool $$tool" ; exit 1); done
	-rm -rf dist tracee-ebpf/dist tracee-rules/dist
	$(MAKE) docker docker-slim
	-rm -rf dist tracee-ebpf/dist tracee-rules/dist
	$(MAKE) release2

release_notes := $(OUT_DIR)/release-notes.txt
.PHONY: release2
# before running this rule, need to authenticate git, gh, and docker tools
release2: $(OUT_ARCHIVE) $(OUT_CHECKSUMS)
	-rm $(release_notes)
	echo '## Changelog' > $(release_notes)
	$(CMD_GIT) log --pretty=oneline --abbrev=commit --no-decorate --no-color tags/$(shell $(CMD_GIT) describe --tags --abbrev=0)..HEAD >> $(release_notes)
	echo '' >> $(release_notes)
	echo '## Docker images' >> $(release_notes)
	$(foreach img,$(release_images_fat),$(call release_docker_image,$(OUT_DOCKER):latest,$(img)))
	$(foreach img,$(release_images_slim),$(call release_docker_image,$(OUT_DOCKER):slim,$(img)))
	echo '' >>$(release_notes)
	$(foreach MODULE_TAG,$(MODULE_TAG_NAMES),$(CMD_GIT) tag -f $(MODULE_TAG);)
	$(foreach MODULE_TAG,$(MODULE_TAG_NAMES),$(CMD_GIT) push -u origin $(MODULE_TAG);)
	$(CMD_GITHUB) release create $(RELEASE_TAG) $(OUT_ARCHIVE) $(OUT_CHECKSUMS) --title $(RELEASE_TAG) --notes-file $(release_notes)

.PHONY: mostlyclean
mostlyclean:
	-rm -rf $(OUT_DIR)
	-$(MAKE) -C tracee-ebpf mostlyclean
	-$(MAKE) -C tracee-rules mostlyclean

.PHONY: clean
clean:
	-$(CMD_DOCKER) rmi $(OUT_DOCKER) $(release_images_fat) $(release_images_slim)
	-$(MAKE) -C tracee-ebpf clean
	-$(MAKE) -C tracee-rules clean

.PHONY: test-entrypoint
test-entrypoint: entrypoint.sh entrypoint_test.bats test/mocks/* test/bats-helpers.bash
	@command -v $$BATS >/dev/null || (echo "missing required tool $$BATS"; false)
	bats ./entrypoint_test.bats
