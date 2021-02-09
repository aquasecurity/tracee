OUT_DIR ?= dist
OUT_DOCKER ?= tracee
OUT_ARCHIVE := $(OUT_DIR)/tracee.tar.gz
OUT_CHECKSUMS := $(OUT_DIR)/checksums.txt
PUSH_DOCKER_REPO ?= aquasec/tracee
PUSH_DOCKER_TAG ?= $(RELEASE_TAG:v%=%)
RELEASE_FILES := LICENSE $(OUT_DIR)/tracee-ebpf $(OUT_DIR)/tracee-rules $(OUT_DIR)/rules
# RELEASE_TAG must be set for the release target
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags 2>/dev/null || echo '0'))

CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_CHECKSUM ?= sha256sum
CMD_GITHUB ?= gh
CMD_TAR ?= tar
CMD_CP ?= cp

release_tools := $(CMD_DOCKER) $(CMD_GIT) $(CMD_CHECKSUM) $(CMD_GITHUB) $(CMD_TAR) $(CMP_CP)
check_release_tools := $(shell for tool in $(release_tools); do command -v $$tool >/dev/null || (echo "missing required tool $$tool" ; false); done)

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

$(OUT_ARCHIVE) $(OUT_CHECKSUMS) &: $(RELEASE_FILES) | $(OUT_DIR)
	$(CMD_TAR) -czf $(OUT_ARCHIVE) $(RELEASE_FILES)
	$(CMD_CHECKSUM) $(OUT_ARCHIVE) > $(OUT_CHECKSUMS)

.PHONY: docker
docker:
	$(CMD_DOCKER) build --build-arg VERSION=$(VERSION) -t $(OUT_DOCKER):latest .

.PHONY: docker-slim
docker-slim:
	$(CMD_DOCKER) build --build-arg VERSION=$(VERSION) -t $(OUT_DOCKER):slim --build-arg BASE=slim .

# release_docker_image accepts a docker image $1, pushes it as $2 to remote repository, and records it in the release notes
define release_docker_image
	$(CMD_DOCKER) tag $(1) $(2) && $(CMD_DOCKER) push $(2) && echo '- `docker pull docker.io/$(2)`' >> $(release_notes);
endef

release_notes := $(OUT_DIR)/release-notes.txt
release_images_fat := $(PUSH_DOCKER_REPO):latest $(PUSH_DOCKER_REPO):$(PUSH_DOCKER_TAG)
release_images_slim := $(PUSH_DOCKER_REPO):slim $(PUSH_DOCKER_REPO):slim-$(PUSH_DOCKER_TAG)
.PHONY: release
# before running this rule, need to authenticate git, gh, and docker tools
release: $(OUT_ARCHIVE) $(OUT_CHECKSUMS) | docker $(check_release_tools)
	test -n '$(RELEASE_TAG)' || (echo "missing required variable RELEASE_TAG" ; false)
	-rm $(release_notes)
	echo '## Changelog' > $(release_notes)
	$(CMD_GIT) log --pretty=oneline --abbrev=commit --no-decorate --no-color tags/$(shell $(CMD_GIT) describe --tags --abbrev=0)..HEAD >> $(release_notes)
	echo '' >> $(release_notes)
	echo '## Docker images' >> $(release_notes)
	$(foreach img,$(release_images_fat),$(call release_docker_image,$(OUT_DOCKER):latest,$(img)))
	$(foreach img,$(release_images_slim),$(call release_docker_image,$(OUT_DOCKER):slim,$(img)))
	echo '' >>$(release_notes)
	$(CMD_GIT) tag $(RELEASE_TAG)
	$(CMD_GIT) push origin $(RELEASE_TAG)
	$(CMD_GITHUB) release create $(RELEASE_TAG) $(OUT_ARCHIVE) $(OUT_CHECKSUMS) --title $(RELEASE_TAG) --notes-file $(release_notes)

.PHONY: mostlyclean
mostlyclean:
	-rm -rf $(OUT_DIR)
	-$(MAKE) -C tracee-ebpf mostlyclean
	-$(MAKE) -C tracee-rules mostlyclean

.PHONY: clean
clean:
	-$(CMD_DOCKER) rmi $(OUT_DOCKER) $(release_images_fat) $(release_images_slim)
	-$(MAKE) -c tracee-ebpf clean
	-$(MAKE) -c tracee-rules clean
