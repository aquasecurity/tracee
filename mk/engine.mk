#
# Container engine detection and run-argument composition.
#
# Engine-neutral: works with docker and podman (rootful and rootless),
# including rootless podman on SELinux-enforcing hosts. Override the engine
# with CONTAINER_ENGINE=podman (or =docker).
#

CONTAINER_ENGINE ?=
ifeq ($(CONTAINER_ENGINE),)
  ifneq ($(shell command -v docker 2> /dev/null),)
    CONTAINER_ENGINE := docker
  else ifneq ($(shell command -v podman 2> /dev/null),)
    CONTAINER_ENGINE := podman
  endif
endif
ifeq ($(CONTAINER_ENGINE),)
  $(error no container engine found (docker or podman); install one, or run \
    with NATIVE=1 if the host has a full build toolchain)
endif

# docker may be the podman-docker shim: classify by --version output
ENGINE_IS_PODMAN := $(if $(findstring podman,\
	$(shell $(CONTAINER_ENGINE) --version 2> /dev/null)),1)

# call the shim by its real name (clear output, and silences the shim's
# 'Emulate Docker CLI using podman' notice)
ifeq ($(ENGINE_IS_PODMAN)-$(CONTAINER_ENGINE),1-docker)
  CONTAINER_ENGINE := podman
endif

UID := $(shell id -u)
GID := $(shell id -g)
NPROC := $(shell nproc 2> /dev/null || echo 1)

# rootless podman: fine for builds and unprivileged targets; privileged
# targets (eBPF loading) transparently prefix the engine with sudo
ENGINE_ROOTLESS := $(if $(ENGINE_IS_PODMAN),$(if $(filter 0,$(UID)),,1))

SELINUX_ENFORCING := $(shell [ "$$(getenforce 2> /dev/null)" = "Enforcing" ] && echo 1)

#
# run-argument profiles
#

# base profile: builds, checks, unit tests - no privileges needed
ENGINE_RUN_BASE := --rm \
	-v $(CURDIR):/tracee \
	-w /tracee \
	-e TRACEE_BUILDENV=1 \
	-e MAKEFLAGS=--no-print-directory

# a real PID 1 (signal forwarding, zombie reaping) instead of the inner
# make - only for private PID namespaces: --init cannot be combined with
# the privileged profile's --pid=host (and is unnecessary there, orphans
# reparent to the host init)
ENGINE_RUN_INIT := --init

ifeq ($(SELINUX_ENFORCING),1)
  # label=disable instead of :z - :z recursively relabels the whole source
  # tree on the host; disabling separation for this container does not
  ENGINE_RUN_BASE += --security-opt label=disable
endif

# rootless podman: with the default userns mapping, container root IS the
# invoking host user - bind-mounted artifacts keep host ownership, and
# root-gated unit tests (assureIsRoot -> t.Skip) actually run instead of
# silently skipping, matching the old root-in-container CI behavior
ENGINE_RUN_ROOTLESS := --user root --pull=never

# interactive terminal only when stdin is one (CI pipes get neither flag)
ENGINE_TTY := $(shell [ -t 0 ] && echo "-it")

# privileged profile: integration/e2e/performance tests - tracee needs the
# host kernel, and container-runtime tests need the host engine socket
# (podman's socket speaks the docker API; mount it at the default path).
# Probe with test -S: podman-docker ships /var/run/docker.sock as a symlink
# that dangles unless the rootful podman.socket unit is active, and a
# dangling mount source makes the engine fail.
ENGINE_SOCK := $(shell for s in \
	/var/run/docker.sock \
	/run/podman/podman.sock \
	$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}/podman/podman.sock; do \
	if [ -S "$${s}" ]; then echo "$${s}"; break; fi; done)

# under a rootless engine the privileged run escalates with sudo anyway, so
# mount the ROOTFUL podman socket: containers the tests spawn then run as
# real uid 0 (the rootless socket would put them in the user's userns and
# tracee would report uid 1000). The dispatch recipe transiently starts
# podman.socket with the already-authorized sudo before the run.
ENGINE_SOCK_PRIV := $(if $(ENGINE_ROOTLESS),/run/podman/podman.sock,$(ENGINE_SOCK))
ENGINE_RUN_PRIV := \
	--user root \
	--pid=host \
	--cgroupns=host \
	--network=host \
	--privileged \
	-v /etc/os-release:/etc/os-release-host:ro \
	-e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
	-v /var/run:/var/run:ro \
	$(if $(wildcard /boot/config-$(shell uname -r)),-v /boot/config-$(shell uname -r):/boot/config-$(shell uname -r):ro) \
	$(if $(wildcard /sys/kernel/security),-v /sys/kernel/security:/sys/kernel/security:ro) \
	$(if $(wildcard /sys/kernel/debug),-v /sys/kernel/debug:/sys/kernel/debug:rw) \
	-v /tmp/tracee:/tmp/tracee:rw \
	$(if $(wildcard /dev/kvm),--device /dev/kvm) \
	$(if $(ENGINE_SOCK_PRIV),-v $(ENGINE_SOCK_PRIV):/var/run/docker.sock)

# host Go cache mounts: containers are ephemeral (--rm), so without these
# every run re-downloads modules and rebuilds from scratch. Default to the
# host's own caches (shared with native go usage; module cache is source-only
# and the build cache is keyed by toolchain+flags, so musl/glibc/host entries
# coexist safely). Override with TRACEE_HOST_GO*=<dir>, or set empty to
# disable. Note: privileged runs execute as root, so entries they add come
# out root-owned ('go clean -modcache' may then need sudo).
TRACEE_HOST_GOCACHE ?= $(or $(shell go env GOCACHE 2> /dev/null),$(HOME)/.cache/go-build)
TRACEE_HOST_GOMODCACHE ?= $(or $(shell go env GOMODCACHE 2> /dev/null),$(HOME)/go/pkg/mod)
ENGINE_RUN_GOCACHE := \
	$(if $(TRACEE_HOST_GOCACHE),-v $(TRACEE_HOST_GOCACHE):/home/tracee/.cache/go-build) \
	$(if $(TRACEE_HOST_GOMODCACHE),-v $(TRACEE_HOST_GOMODCACHE):/home/tracee/go/pkg/mod)

# Everything a privileged (real-root, sudo) container run writes that must be
# handed back to the invoking user before it exits - so a rootless-engine host
# is never left with root-owned files. Container-side paths: the repo build
# outputs and coverage, the bind-mounted host Go caches, and the /tmp/tracee
# scratch (tracee workdir + the e2e artifacts collected there for host debug).
# Single list so the two chown-back recipes and any future consumer stay in sync.
ENGINE_CHOWN_BACK := \
	/tracee/dist /tracee/*coverage*.txt \
	/home/tracee/.cache/go-build /home/tracee/go/pkg/mod \
	/tmp/tracee

#
# variable passthrough
#
# Only variables set on the command line or in the environment are forwarded
# (explicit -e allowlist: MAKEOVERRIDES would word-split quoted values).
#

FWD_VARS := \
	ARG \
	ARGS \
	BASE_REF \
	BTFHUB \
	DEBUG \
	E2E_ARGS \
	FIPS \
	INSTTESTS \
	METRICS \
	NETTESTS \
	PKG \
	RELEASE_VERSION \
	SNAPSHOT \
	STATIC \
	STRIP_BPF_DEBUG \
	TEST \
	TESTS

ENGINE_RUN_ENV := $(foreach v,$(FWD_VARS),\
	$(if $(filter command line environment,$(origin $(v))),-e $(v)='$($(v))'))
