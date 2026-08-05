#
# Host orchestrator: forward the requested goals into the build container.
#
# Included by the root Makefile only in 'dispatch' context (see
# mk/context.mk). The real recipes (mk/tracee.mk) are NOT parsed here; for
# every requested goal that is not host-only, a forwarding rule is generated
# from MAKECMDGOALS, so unknown goals (including private-overlay goals)
# forward transparently. All buildenv goals of one invocation run in a
# single container run, preserving their order.
#

include mk/engine.mk
include mk/images.mk
include mk/dev.mk

# private overlay hook: may extend HOST_ONLY_GOALS / PRIVILEGED_GOALS and
# define custom host-side targets (guard recipes with TRACEE_RUN_CONTEXT)
-include Makefile.extended-pre

#
# goal classification
#

# goals that must run on the host (never in a container)
HOST_ONLY_GOALS += \
	help \
	clean \
	image images image-vm image-distro-test clean-images \
	fix-cache-perms \
	stop-buildenv \
	shell \
	dev dev-stop dev-ssh attach clean-dev \
	lsp-go lsp-c lsp-print-go lsp-print-c \
	check-pr check-pr-fast check-pr-skip-docs check-pr-skip-tests \
	format-pr \
	evt-trigger-runner clean-evt-trigger-runner \
	bench-network \
	mkdocs-build mkdocs-serve

# goals needing the privileged run profile (host kernel access); under a
# rootless engine these transparently run with sudo
PRIVILEGED_GOALS += \
	run run-traceectl run-evt \
	tests tests-e2e \
	test-integration \
	test-compatibility \
	test-performance \
	test-e2e test-e2e-net test-e2e-kernel test-e2e-vm \
	test-upstream-libbpfgo

GOALS := $(or $(MAKECMDGOALS),all)
CTR_GOALS := $(filter-out $(HOST_ONLY_GOALS),$(GOALS))

# per-goal image mapping: purpose images carry a single tool; everything
# else runs in the buildenv image (clean-man only removes files, so it does
# not need the pandoc image)
MAN_GOALS := $(filter man,$(CTR_GOALS))
BEAR_GOALS := $(filter bear,$(CTR_GOALS))
PROTOC_GOALS := $(filter protoc,$(CTR_GOALS))
K8S_GOALS := $(filter k8s-manifests k8s-generate,$(CTR_GOALS))
BUILDENV_GOALS := $(filter-out $(MAN_GOALS) $(PROTOC_GOALS) $(K8S_GOALS) $(BEAR_GOALS),$(CTR_GOALS))

NEED_PRIV := $(filter $(PRIVILEGED_GOALS),$(BUILDENV_GOALS))

# integration tests exercise the userland as much as the kernel (coreutils
# paths, PAM files, glibc ld.so.cache) and are calibrated for Ubuntu: default
# them to the ubuntu environment unless DISTRO was given explicitly
ifneq ($(filter test-integration,$(BUILDENV_GOALS)),)
  ifeq ($(filter command line environment,$(origin DISTRO)),)
    override DISTRO := ubuntu
  endif
endif

# test-e2e-vm (and the `tests` aggregate, which includes it) run in the opt-in
# VM-capable image (firecracker + qemu + ext4 tooling), a distinct stage/tag from the
# plain dev images - a superset of :ubuntu, so the non-VM suites in `tests` run
# in it fine too, keeping the whole aggregate in ONE container (one sudo). The
# VM boots the HOST's running kernel, so bind-mount its image, config,
# modules and build headers read-only for the runner to extract vmlinux and
# assemble the guest rootfs (only for these goals - other runs never see them).
BUILDENV_TARGET := $(DISTRO)-dev
VM_HOST_KERNEL_MOUNTS :=
ifneq ($(filter test-e2e-vm tests tests-e2e,$(BUILDENV_GOALS)),)
  override DISTRO := ubuntu
  override BUILDENV_IMAGE := tracee-buildenv:ubuntu-vm
  BUILDENV_TARGET := ubuntu-vm
  FC_KREL := $(shell uname -r)
  VM_HOST_KERNEL_MOUNTS := \
    $(if $(wildcard /boot/vmlinuz-$(FC_KREL)),-v /boot/vmlinuz-$(FC_KREL):/boot/vmlinuz-$(FC_KREL):ro) \
    $(if $(wildcard /lib/modules/$(FC_KREL)),-v /lib/modules/$(FC_KREL):/lib/modules/$(FC_KREL):ro) \
    $(if $(wildcard /usr/src),-v /usr/src:/usr/src:ro)
endif

# The kernel-tampering test modules must be built with the RUNNING kernel's own
# toolchain. The Ubuntu buildenv container cannot build a module for a foreign
# kernel (e.g. a Fedora host: GNU Make 4.3 vs the kernel tree's 4.4.1 recurses
# forever; gcc/pahole also differ), so pre-build them natively on the HOST here,
# before the container runs. The runner copies the .ko into the guest and the
# test scripts reuse them (E2E_PREBUILT_MODULE). Best-effort: if the host lacks
# a kernel-module toolchain the guest builds them itself, which is fine when the
# guest userland matches the host kernel (the Ubuntu CI AMIs).
#
# `clean` FIRST: a stale main object left in the tree (e.g. a hijack.o built by
# an older toolchain without -fcf-protection=branch) has no kbuild .cmd record
# and can be newer than the .c, so `modules` would relink it as-is instead of
# recompiling - producing a .ko whose init lacks endbr64, which an IBT kernel
# (CONFIG_X86_KERNEL_IBT) rejects with a "Missing ENDBR" BUG at insmod. Cleaning
# forces a fresh compile against the running kernel's tree, which injects the
# IBT flag.
FC_MODULE_DIRS := tests/e2e/core/scripts/hooker tests/e2e/core/scripts/hijack
define fc_prebuild_modules
kdir=/lib/modules/$(FC_KREL)/build; \
if command -v make > /dev/null 2>&1 && { command -v gcc > /dev/null 2>&1 || command -v cc > /dev/null 2>&1; } && [ -d "$${kdir}" ]; then \
	echo "[e2e-vm] pre-building test modules on the host ($${kdir})..."; \
	for m in $(FC_MODULE_DIRS); do \
		$(MAKE) -C "$${kdir}" M="$(CURDIR)/$${m}" clean > /dev/null 2>&1 || true; \
		if $(MAKE) -C "$${kdir}" M="$(CURDIR)/$${m}" modules > /dev/null 2>&1; then \
			echo "[e2e-vm]   built $${m}/$$(basename $${m}).ko"; \
		else \
			echo "[e2e-vm]   WARN: host build of $${m} failed; the guest will try to build it"; \
		fi; \
	done; \
else \
	echo "[e2e-vm] host has no kernel-module toolchain; modules will build inside the guest"; \
fi
endef

#
# engine invocation
#

# privileged goals need real root for eBPF: prefix a rootless engine with
# sudo (note: sudo uses a separate image store, so the image may build twice)
ENGINE_PRIV := $(if $(ENGINE_ROOTLESS),sudo )$(CONTAINER_ENGINE)
ENGINE := $(if $(NEED_PRIV),$(ENGINE_PRIV),$(CONTAINER_ENGINE))

# keep-id only for the rootless engine itself (never combined with sudo)
ENGINE_RUN_USERNS := $(if $(NEED_PRIV),,$(if $(ENGINE_ROOTLESS),$(ENGINE_RUN_ROOTLESS)))

ENGINE_RUN_ARGS = $(ENGINE_RUN_BASE) $(ENGINE_RUN_USERNS) $(ENGINE_RUN_GOCACHE) \
	$(if $(NEED_PRIV),$(ENGINE_RUN_PRIV),$(ENGINE_RUN_INIT)) $(VM_HOST_KERNEL_MOUNTS) \
	$(ENGINE_RUN_ENV) $(ENGINE_TTY)

# purpose images run as root inside (no baked user); under rootless podman
# the default userns already maps container root to the invoking user
ENGINE_RUN_PURPOSE = $(ENGINE_RUN_BASE) $(ENGINE_RUN_INIT) $(ENGINE_RUN_ENV) $(ENGINE_TTY)

# jobserver file descriptors cannot cross the container boundary: pass an
# explicit job count so the C side (libbpf, BPF objects) builds in parallel
INNER_MAKE = make -j$(NPROC)

# rootless podman (ENGINE_ROOTLESS is only ever set for podman - see
# mk/engine.mk): bring up the rootful API socket (transient, not enabled at
# boot) so test-spawned containers run as real uid 0 - the sudo used here is
# the one already authorized for the privileged run itself. The socket check
# must be run-time (same shell), not $(wildcard): that evaluates at parse
# time, before systemctl has run. Needed by every user of ENGINE_RUN_PRIV,
# which mounts this socket.
# the socket check needs sudo too: /run/podman is root-only, so a plain
# test -S fails for the invoking user even when the socket is live
define start_rootful_socket
sudo systemctl start podman.socket 2> /dev/null; \
if sudo test -S /run/podman/podman.sock 2> /dev/null; then \
	echo "[buildenv] using rootful podman socket for test containers (uid 0)"; \
else \
	echo "[buildenv] warning: rootful podman.socket unavailable - container-runtime tests may fail"; \
fi
endef

#
# forwarding rules
#

ifneq ($(BUILDENV_GOALS),)
.PHONY: $(BUILDENV_GOALS) .run-buildenv
$(BUILDENV_GOALS): .run-buildenv
	@:
.run-buildenv:
	$(if $(and $(NEED_PRIV),$(ENGINE_ROOTLESS)),@echo "[buildenv] '$(NEED_PRIV)' needs a rootful engine (eBPF): using 'sudo $(CONTAINER_ENGINE)' - authentication may be prompted")
	@$(call ensure_image,$(BUILDENV_IMAGE),$(BUILDENV_TARGET),$(CONTAINER_ENGINE))
	$(if $(and $(NEED_PRIV),$(ENGINE_ROOTLESS)),@$(call ensure_image_rootful,$(BUILDENV_IMAGE)))
	$(if $(NEED_PRIV),@mkdir -p /tmp/tracee)
# test-e2e-vm (and `tests`): build the kernel test modules on the host (matching
# toolchain) before the container run; the runner copies the .ko into the guest
	$(if $(filter test-e2e-vm tests tests-e2e,$(BUILDENV_GOALS)),@$(call fc_prebuild_modules))
# bind-mount sources must exist before the engine runs
	$(if $(TRACEE_HOST_GOCACHE),@mkdir -p $(TRACEE_HOST_GOCACHE))
	$(if $(TRACEE_HOST_GOMODCACHE),@mkdir -p $(TRACEE_HOST_GOMODCACHE))
	$(if $(and $(NEED_PRIV),$(ENGINE_ROOTLESS)),-@$(call start_rootful_socket))
	$(if $(and $(NEED_PRIV),$(if $(ENGINE_ROOTLESS),,1),$(if $(ENGINE_SOCK),,1)),@echo "[buildenv] warning: no live engine socket found - container-runtime tests will fail/skip (start docker)")
# privileged runs execute as real root, so anything they write into the
# bind-mounted tree comes out root-owned: hand ownership back before the
# container exits (even on failure) - in-container, where root is free,
# so no second sudo prompt after a long run
	$(if $(NEED_PRIV),$(ENGINE) run $(ENGINE_RUN_ARGS) $(BUILDENV_IMAGE) sh -c \
		'$(INNER_MAKE) $(BUILDENV_GOALS); rc=$$?; \
		cp -f /tmp/tracee-log-* /tmp/tracee-output-* /tmp/e2e-*.log /tmp/tracee/ 2> /dev/null || true; \
		chown -R $(UID):$(GID) $(ENGINE_CHOWN_BACK) 2> /dev/null; \
		exit $${rc}',$(ENGINE) run $(ENGINE_RUN_ARGS) $(BUILDENV_IMAGE) $(INNER_MAKE) $(BUILDENV_GOALS))
endif

# The recipe files are not parsed in dispatch context, so their target names
# would be invisible to shell completion (which reads make's rule database)
# and to prerequisite resolution. Parse them out and define catch-up rules
# for every known goal that was not requested; each re-enters make, where it
# is classified and forwarded normally.
KNOWN_GOALS := $(shell grep -hE '^[a-zA-Z][a-zA-Z0-9_-]*::?([^=].*)?$$' \
	mk/tracee.mk mk/checks.mk 2> /dev/null | cut -d: -f1 | sort -u)

COMPLETION_GOALS := $(filter-out $(GOALS) $(HOST_ONLY_GOALS),$(KNOWN_GOALS))
ifneq ($(COMPLETION_GOALS),)
.PHONY: $(COMPLETION_GOALS)
$(COMPLETION_GOALS):
	@$(MAKE) $@
endif

# bear runs with the repo mounted AT ITS HOST PATH, so the
# compile_commands.json it generates is directly usable by a host clangd
# (no /tracee path translation); a dedicated build context keeps the
# host-path goenv/stamps from poisoning the /tracee-mounted ones
ifneq ($(BEAR_GOALS),)
.PHONY: $(BEAR_GOALS) .run-bear
$(BEAR_GOALS): .run-bear
	@:
.run-bear:
	@$(call ensure_image,$(BUILDENV_IMAGE),$(DISTRO)-dev,$(CONTAINER_ENGINE))
	$(if $(TRACEE_HOST_GOCACHE),@mkdir -p $(TRACEE_HOST_GOCACHE))
	$(if $(TRACEE_HOST_GOMODCACHE),@mkdir -p $(TRACEE_HOST_GOMODCACHE))
	$(CONTAINER_ENGINE) run --rm \
		$(if $(SELINUX_ENFORCING),--security-opt label=disable) \
		$(if $(ENGINE_ROOTLESS),$(ENGINE_RUN_ROOTLESS),--user $(UID):$(GID)) \
		$(ENGINE_RUN_INIT) $(ENGINE_RUN_GOCACHE) \
		-e TRACEE_BUILDENV=1 \
		-e TRACEE_BUILDENV_DISTRO=$(DISTRO)-hostpath \
		-v "$(CURDIR):$(CURDIR)" \
		-w "$(CURDIR)" \
		$(ENGINE_RUN_ENV) $(ENGINE_TTY) \
		$(BUILDENV_IMAGE) $(INNER_MAKE) $(BEAR_GOALS)
endif

ifneq ($(MAN_GOALS),)
.PHONY: $(MAN_GOALS) .run-man
$(MAN_GOALS): .run-man
	@:
.run-man:
	@$(call ensure_image,tracee-man:latest,man,$(CONTAINER_ENGINE))
# rootful engines need the uid mapped so generated pages come out
# host-owned; under rootless podman container ROOT already is the invoking
# user, and --user $(UID) there would map to a subuid instead
	$(CONTAINER_ENGINE) run $(ENGINE_RUN_PURPOSE) \
		$(if $(ENGINE_ROOTLESS),,--user $(UID):$(GID)) \
		tracee-man:latest make $(MAN_GOALS)
endif

ifneq ($(PROTOC_GOALS),)
.PHONY: $(PROTOC_GOALS) .run-protoc
$(PROTOC_GOALS): .run-protoc
	@:
.run-protoc:
	@$(call ensure_image,tracee-protoc:latest,protoc,$(CONTAINER_ENGINE))
	$(CONTAINER_ENGINE) run $(ENGINE_RUN_PURPOSE) tracee-protoc:latest \
		make $(PROTOC_GOALS)
endif

ifneq ($(K8S_GOALS),)
.PHONY: $(K8S_GOALS) .run-k8s
$(K8S_GOALS): .run-k8s
	@:
.run-k8s:
	@$(call ensure_image,tracee-k8s:latest,k8s,$(CONTAINER_ENGINE))
	$(CONTAINER_ENGINE) run $(ENGINE_RUN_PURPOSE) tracee-k8s:latest \
		make $(K8S_GOALS)
endif

#
# host-side goals
#

# interactive shell in the build environment; use DISTRO=ubuntu for the
# glibc variant. Privileged by default so tracee/eBPF tests run inside;
# PRIV=0 gives an unprivileged shell (builds/checks/unit tests only - no
# sudo, no rootful transfer, root tests inside will skip/fail)
PRIV ?= 1
SHELL_PRIV := $(filter-out 0,$(PRIV))

.PHONY: shell
shell:
	$(if $(and $(SHELL_PRIV),$(ENGINE_ROOTLESS)),@echo "[buildenv] shell is privileged (eBPF): using 'sudo $(CONTAINER_ENGINE)' - authentication may be prompted (PRIV=0 for an unprivileged shell)")
	@$(call ensure_image,$(BUILDENV_IMAGE),$(DISTRO)-dev,$(CONTAINER_ENGINE))
	$(if $(and $(SHELL_PRIV),$(ENGINE_ROOTLESS)),@$(call ensure_image_rootful,$(BUILDENV_IMAGE)))
	$(if $(SHELL_PRIV),@mkdir -p /tmp/tracee)
	$(if $(TRACEE_HOST_GOCACHE),@mkdir -p $(TRACEE_HOST_GOCACHE))
	$(if $(TRACEE_HOST_GOMODCACHE),@mkdir -p $(TRACEE_HOST_GOMODCACHE))
# the privileged profile mounts the rootful socket - it must be live
	$(if $(and $(SHELL_PRIV),$(ENGINE_ROOTLESS)),-@$(call start_rootful_socket))
# '-' prefix: exiting the interactive shell with a non-zero status (e.g.
# your last command failed, or ^D after a failure) is not a make error
	$(if $(SHELL_PRIV),-$(ENGINE_PRIV) run $(ENGINE_RUN_BASE) $(ENGINE_RUN_PRIV) $(ENGINE_RUN_GOCACHE) \
		$(ENGINE_RUN_ENV) -it $(BUILDENV_IMAGE) sh -c \
		'/bin/bash; rc=$$?; \
		chown -R $(UID):$(GID) $(ENGINE_CHOWN_BACK) 2> /dev/null; \
		exit $${rc}',-$(CONTAINER_ENGINE) run $(ENGINE_RUN_BASE) \
		$(if $(ENGINE_ROOTLESS),$(ENGINE_RUN_ROOTLESS)) $(ENGINE_RUN_INIT) \
		$(ENGINE_RUN_GOCACHE) $(ENGINE_RUN_ENV) -it $(BUILDENV_IMAGE) /bin/bash)

# kill leftover buildenv containers (an interrupted run can orphan one:
# the engine client dies with ^C but conmon keeps the container alive)
.PHONY: stop-buildenv
stop-buildenv:
	-@ids=$$($(CONTAINER_ENGINE) ps -q \
		$(foreach d,$(SUPPORTED_DISTROS),--filter ancestor=tracee-buildenv:$(d))); \
	[ -n "$${ids}" ] && echo "$${ids}" | xargs $(CONTAINER_ENGINE) kill; \
	true
	$(if $(ENGINE_ROOTLESS),-@ids=$$(sudo -n $(CONTAINER_ENGINE) ps -q \
		$(foreach d,$(SUPPORTED_DISTROS),--filter ancestor=tracee-buildenv:$(d)) 2> /dev/null); \
	[ -n "$${ids}" ] && echo "$${ids}" | xargs sudo -n $(CONTAINER_ENGINE) kill; \
	true)

# Reclaim ownership of caches/artifacts that an earlier privileged run left
# root-owned. Privileged runs execute as real root (sudo podman, or the docker
# daemon), so files they add to the bind-mounted host Go caches and /tmp/tracee
# come out root-owned. The end-of-run chown-back (ENGINE_CHOWN_BACK) now handles
# this automatically; this target reclaims anything left over from before, or
# from an interrupted run. Needs sudo to chown root-owned files.
.PHONY: fix-cache-perms
fix-cache-perms:
	@echo "[buildenv] reclaiming ownership of caches/artifacts from earlier privileged runs - authentication may be prompted"
	-sudo chown -R $(UID):$(GID) \
		$(if $(TRACEE_HOST_GOCACHE),$(TRACEE_HOST_GOCACHE)) \
		$(if $(TRACEE_HOST_GOMODCACHE),$(TRACEE_HOST_GOMODCACHE)) \
		/tmp/tracee 2> /dev/null
	@echo "[buildenv] done"

# full wipe without needing a container; also sweeps legacy root-level
# stamp files from the pre-mk/ layout
.PHONY: clean
clean:
	rm -rf ./dist
	rm -f goenv.mk .*.md5 .build_libbpf* .check* .eval_goenv* .*-pkgs*

# PR verification runs on the host: checkpatch.sh re-invokes make targets
# that containerize themselves (no docker-in-docker)
.PHONY: check-pr check-pr-fast check-pr-skip-docs check-pr-skip-tests format-pr
check-pr::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh $(if $(ARGS),$(ARGS),HEAD)
check-pr-fast::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --fast HEAD
check-pr-skip-docs::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --skip-docs HEAD
check-pr-skip-tests::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) ./scripts/checkpatch.sh --skip-unit-tests HEAD
format-pr::
	@$(if $(BASE_REF),BASE_REF=$(BASE_REF)) $(CURDIR)/scripts/checkpatch.sh pr-format

.PHONY: evt-trigger-runner clean-evt-trigger-runner
evt-trigger-runner:
	$(MAKE) -f builder/Makefile.evt-trigger-runner build
clean-evt-trigger-runner:
	$(MAKE) -f builder/Makefile.evt-trigger-runner clean

.PHONY: bench-network
bench-network::
	./performance/benchmark/network/bench.sh $(IMAGE) $(OUTPUT) $(TIME)

MKDOCS_IMAGE := tracee-mkdocs:latest

.PHONY: mkdocs-build
mkdocs-build:
	@$(call ensure_image,$(MKDOCS_IMAGE),mkdocs,$(CONTAINER_ENGINE))
	$(CONTAINER_ENGINE) run --rm \
		$(if $(SELINUX_ENFORCING),--security-opt label=disable) \
		-v $(CURDIR):/docs \
		$(MKDOCS_IMAGE) build

.PHONY: mkdocs-serve
mkdocs-serve:
	@$(call ensure_image,$(MKDOCS_IMAGE),mkdocs,$(CONTAINER_ENGINE))
	$(CONTAINER_ENGINE) run --rm \
		$(if $(SELINUX_ENFORCING),--security-opt label=disable) \
		-v $(CURDIR):/docs \
		-p 8000:8000 $(ENGINE_TTY) \
		$(MKDOCS_IMAGE)

# private overlay hook
-include Makefile.extended-post
