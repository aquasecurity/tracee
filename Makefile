#
# Tracee build system entrypoint.
#
# All goals run inside the containerized build environment by default: on
# the host this file dispatches into the buildenv image (mk/dispatch.mk);
# inside the container (or with NATIVE=1) the real recipes run
# (mk/tracee.mk). See mk/context.mk for the detection.
#
#   make [all|tracee|bpf|check-fmt|test-unit|...]   # containerized
#   make ... DISTRO=ubuntu                          # glibc build env
#   make ... NATIVE=1                               # host toolchain
#   make shell                                      # interactive build env
#   make image / images / clean-images              # image lifecycle
#
# Note: the Makefile.extended-pre/-post overlay hooks are included by
# mk/tracee.mk and mk/dispatch.mk (inclusion order relative to their
# variable definitions is significant), not here.
#

.DEFAULT_GOAL := all

include mk/context.mk

ifeq ($(TRACEE_RUN_CONTEXT),dispatch)
include mk/dispatch.mk
else
include mk/tracee.mk
endif

include mk/help.mk
