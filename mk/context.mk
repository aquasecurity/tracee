#
# Run-context detection.
#
# The root Makefile includes mk/dispatch.mk (host orchestrator: forwards
# goals into the build container) or mk/tracee.mk (the real recipes) based
# on TRACEE_RUN_CONTEXT:
#
#   container - TRACEE_BUILDENV is set in the environment (baked into the
#               buildenv images and passed by the dispatcher): we ARE the
#               in-container make, run recipes natively. Any recursive
#               $(MAKE) inherits it, so nested engine launches are
#               impossible.
#   native    - NATIVE=1: escape hatch for hosts with a full toolchain.
#   dispatch  - anything else: forward goals into the build container.
#
# BUILD_CONTEXT keys per-context build state (dist/.ctx/<context>) so host,
# alpine and ubuntu artifacts never mix.
#

NATIVE ?= 0
export NATIVE

ifeq ($(origin TRACEE_BUILDENV),environment)
  TRACEE_RUN_CONTEXT := container
  BUILD_CONTEXT := $(or $(TRACEE_BUILDENV_DISTRO),container)
else ifeq ($(NATIVE),1)
  TRACEE_RUN_CONTEXT := native
  BUILD_CONTEXT := host
else
  TRACEE_RUN_CONTEXT := dispatch
  BUILD_CONTEXT := host
endif
