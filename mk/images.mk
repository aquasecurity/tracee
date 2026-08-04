#
# Build-environment image lifecycle.
#
# Images are LOCAL ONLY (never pushed). Staleness is tracked with an image
# label carrying a hash of everything the image is built from: when the
# Containerfile or an installation script changes, the next make invocation
# rebuilds automatically; otherwise the existing image is reused. Stateless:
# survives 'make clean' and works across worktrees.
#

DISTRO ?= alpine
SUPPORTED_DISTROS := alpine ubuntu
ifeq ($(filter $(DISTRO),$(SUPPORTED_DISTROS)),)
  $(error DISTRO must be one of: $(SUPPORTED_DISTROS))
endif

BUILDENV_IMAGE ?= tracee-buildenv:$(DISTRO)
CONTAINERFILE := builder/Containerfile

IMAGE_HASH_LABEL := org.tracee.buildenv.hash
IMAGE_SRC := $(CONTAINERFILE) $(sort $(wildcard scripts/lib*.sh)) \
	$(sort $(wildcard scripts/installation/*.sh)) \
	$(sort $(wildcard scripts/installation/checksums/*)) \
	$(sort $(wildcard scripts/installation/keys/*))
IMAGE_HASH := $(shell cat $(IMAGE_SRC) 2> /dev/null | md5sum | cut -d' ' -f1)-$(UID)-$(GID)

# distro-test rootfs matrix (see the distro-test stage in the Containerfile):
# the statically built tracee is bind-mounted at run time, so these images
# are pure rootfs and never rebuild with the source
DISTRO_TEST_IMAGE ?= fedora:43

# Build $(1) from Containerfile target $(2) with engine $(3) unless an image
# with the current hash label already exists in that engine's store. Builds
# always run with the ROOTLESS engine; the rootful store only ever receives
# images via ensure_image_rootful's save|load transfer.
define ensure_image
have=$$($(3) image inspect \
	--format '{{ index .Config.Labels "$(IMAGE_HASH_LABEL)" }}' \
	$(1) 2> /dev/null); \
if [ "$${have}" != "$(IMAGE_HASH)" ]; then \
	echo "[buildenv] $(1) missing or stale, building (--target $(2))..."; \
	$(3) build \
		--network host \
		-f $(CONTAINERFILE) \
		--target $(2) \
		--build-arg uid=$(UID) \
		--build-arg gid=$(GID) \
		--label $(IMAGE_HASH_LABEL)=$(IMAGE_HASH) \
		-t $(1) \
		. ; \
fi
endef

# Privileged runs under a rootless engine execute via sudo, whose image
# store is separate. Images are never BUILT as root: build rootless, then
# transfer to the rootful store when its copy is missing or stale.
define ensure_image_rootful
have=$$(sudo $(CONTAINER_ENGINE) image inspect \
	--format '{{ index .Config.Labels "$(IMAGE_HASH_LABEL)" }}' \
	$(1) 2> /dev/null); \
if [ "$${have}" != "$(IMAGE_HASH)" ]; then \
	echo "[buildenv] transferring $(1) to the rootful engine store..."; \
	$(CONTAINER_ENGINE) save $(1) | sudo $(CONTAINER_ENGINE) load; \
fi
endef

.PHONY: image
image:
	@$(call ensure_image,$(BUILDENV_IMAGE),$(DISTRO)-dev,$(CONTAINER_ENGINE))

.PHONY: images
images:
	@for distro in $(SUPPORTED_DISTROS); do \
		$(MAKE) image DISTRO=$${distro} || exit 1; \
	done

# opt-in VM-capable image (firecracker + ext4 tooling) for test-e2e-vm;
# separate tag/stage from the plain dev images
.PHONY: image-fc
image-fc:
	@$(call ensure_image,tracee-buildenv:ubuntu-fc,ubuntu-fc,$(CONTAINER_ENGINE))

.PHONY: image-distro-test
image-distro-test:
	$(CONTAINER_ENGINE) build \
		--network host \
		-f $(CONTAINERFILE) \
		--target distro-test \
		--build-arg DISTRO_TEST_IMAGE=$(DISTRO_TEST_IMAGE) \
		-t tracee-test:$(subst :,-,$(DISTRO_TEST_IMAGE)) \
		.

# removes the local images from the rootless store AND, under a rootless
# engine, the buildenv copies that privileged runs transferred into the
# rootful store (the only images that ever land there)
.PHONY: clean-images
clean-images:
	-$(CONTAINER_ENGINE) image rm -f \
		$(foreach d,$(SUPPORTED_DISTROS),tracee-buildenv:$(d)) \
		tracee-buildenv:ubuntu-fc \
		tracee-man:latest tracee-protoc:latest tracee-k8s:latest \
		tracee-mkdocs:latest 2> /dev/null
	$(if $(ENGINE_ROOTLESS),@echo "[buildenv] cleaning the rootful engine store - authentication may be prompted")
	$(if $(ENGINE_ROOTLESS),-sudo $(CONTAINER_ENGINE) image rm -f \
		$(foreach d,$(SUPPORTED_DISTROS),tracee-buildenv:$(d)) \
		tracee-buildenv:ubuntu-fc 2> /dev/null)
