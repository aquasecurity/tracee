.PHONY: all
all:
	@echo "This make file is intended for releasing only. In order to build any of Tracee's components, use their respective make files."

# RELEASE_TAG must be set to specify a name for the release
OUT_DIR ?= dist
OUT_DOCKER ?= tracee
OUT_ARCHIVE := $(OUT_DIR)/tracee.tar.gz
OUT_CHECKSUMS := $(OUT_DIR)/checksums.txt
PUSH_DOCKER_REPO ?= aquasec/tracee
PUSH_DOCKER_TAG ?= $(RELEASE_TAG:v%=%)

CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_CHECKSUM ?= sha256sum
CMD_GITHUB ?= gh
CMD_TAR ?= tar
CMD_CP ?= cp

release_tools := $(CMD_DOCKER) $(CMD_GIT) $(CMD_CHECKSUM) $(CMD_GITHUB) $(CMD_TAR) $(CMP_CP)
check_release_tools := $(shell for tool in $(release_tools); do command -v $$tool >/dev/null || (echo "missing required tool $$tool" ; false); done)

$(OUT_DIR):
	mkdir -p $@

# make_artifact invokes another make from $1 to make the artifact $2 using additional flags $3
define make_artifact
	$(MAKE) -C $1 dist/$2 $3 OUT_DIR=dist && $(CMD_CP) -r $1/dist/$2 $(OUT_DIR)/$2
endef

$(OUT_DIR)/tracee-ebpf: tracee-ebpf | $(OUT_DIR)
	$(call make_artifact,$<,$(notdir $@),DOCKER=1)

$(OUT_DIR)/tracee-rules $(OUT_DIR)/rules: tracee-rules | $(OUT_DIR)
	$(call make_artifact,$<,$(notdir $@))

release_archive_files := LICENSE $(OUT_DIR)/tracee $(OUT_DIR)/tracee-rules $(OUT_DIR)/rules
$(OUT_ARCHIVE) $(OUT_CHECKSUMS) &: $(release_archive_files) | $(OUT_DIR)
	$(CMD_TAR) -czf $(OUT_ARCHIVE) $(release_archive_files)
	$(CMD_CHECKSUM) $(OUT_ARCHIVE) > $(OUT_CHECKSUMS)

.PHONY: docker
docker: tracee-ebpf
	$(MAKE) -C tracee-ebpf docker docker-slim OUT_DOCKER=$(OUT_DOCKER)

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
