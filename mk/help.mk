#
# usage
#

# one aligned "command # description" line
H = @printf '    %-45s %s\n'

.PHONY: help
help::
	@echo ""
	@echo "# containerized build environment (default)"
	@echo ""
	@echo "    All targets run inside the build environment container by default;"
	@echo "    the image is created automatically on first use."
	@echo ""
	$(H) '$$ make shell' '# interactive shell in the build environment (privileged)'
	$(H) '$$ make shell PRIV=0' '# unprivileged shell (builds/checks; no sudo, no eBPF)'
	$(H) '$$ make image' '# (re)build tracee-buildenv:$$DISTRO if stale'
	$(H) '$$ make images' '# build the build environment for all distros'
	$(H) '$$ make image-fc' '# build the VM-capable image for test-e2e-vm (firecracker)'
	$(H) '$$ make clean-images' '# remove the local build environment images'
	$(H) '$$ make stop-buildenv' '# kill leftover build environment containers'
	@echo ""
	$(H) '$$ make ... DISTRO=ubuntu' '# use the ubuntu (glibc) environment (default: alpine)'
	$(H) '$$ make ... NATIVE=1' '# escape hatch: use the host toolchain instead'
	$(H) '$$ CONTAINER_ENGINE=podman make ...' '# pick the engine (default: docker, then podman)'
	@echo ""
	@echo "# editor / dev box"
	@echo ""
	$(H) '$$ make lsp-go / make lsp-c' '# gopls/clangd over stdio for your editor (host paths)'
	$(H) '$$ make dev' '# start a persistent box to attach your editor to'
	$(H) '$$ make attach' '# print how to attach (TRAMP, VS Code, exec, ssh)'
	$(H) '$$ make dev-stop / make clean-dev' '# stop the box / also remove its home volume'
	@echo ""
	@echo "# privileges"
	@echo ""
	@echo "    No target needs sudo except the ones that load eBPF into the host"
	@echo "    kernel: test-integration, test-compatibility, test-performance,"
	@echo "    test-e2e*, test-upstream-libbpfgo, the tests/tests-e2e aggregates,"
	@echo "    run*, shell. Those use a privileged"
	@echo "    container and chown artifacts back to you afterwards."
	@echo "    - docker: the daemon is already root, so no prompt appears at all."
	@echo "    - rootless podman: the run is escalated with sudo (announced), and"
	@echo "      the rootful podman API socket is started transiently so test"
	@echo "      containers execute as real uid 0."
	@echo ""
	@echo "# environment"
	@echo ""
	$(H) '$$ make env' '# show makefile environment/variables'
	@echo ""
	@echo "# build"
	@echo ""
	$(H) '$$ make all' '# build tracee, signatures & other tools'
	$(H) '$$ make bpf' '# build ./dist/tracee.bpf.o'
	$(H) '$$ make tracee' '# build ./dist/tracee'
	$(H) '$$ make traceectl' '# build ./dist/traceectl (the CLI)'
	$(H) '$$ make tracee-bench' '# build ./dist/tracee-bench'
	$(H) '$$ make signatures' '# build ./dist/signatures'
	$(H) '$$ make tracee-e2e' '# build ./dist/tracee-e2e (with e2e detectors)'
	$(H) '$$ make tracee-e2e-net' '# build ./dist/tracee-e2e-net (with network e2e detectors)'
	$(H) '$$ make tracee-operator' '# build ./dist/tracee-operator'
	$(H) '$$ make lsm-check' '# build ./dist/lsm-check'
	@echo ""
	@echo "# run (privileged: host kernel, network and engine socket)"
	@echo ""
	$(H) '$$ make run ARG="--scope comm=bash"' '# build and run tracee'
	$(H) '$$ make run-traceectl ARG="..."' '# build and run traceectl'
	$(H) '$$ make run-evt ARG="..."' '# build and run evt'
	@echo ""
	@echo "# clean"
	@echo ""
	$(H) '$$ make clean' '# wipe ./dist/'
	$(H) '$$ make clean-bpf' '# wipe ./dist/tracee.bpf.o'
	$(H) '$$ make clean-tracee' '# wipe ./dist/tracee'
	$(H) '$$ make clean-tracee-bench' '# wipe ./dist/tracee-bench'
	$(H) '$$ make clean-signatures' '# wipe ./dist/signatures'
	$(H) '$$ make clean-tracee-operator' '# wipe ./dist/tracee-operator'
	$(H) '$$ make clean-lsm-check' '# wipe ./dist/lsm-check'
	@echo ""
	@echo "# test"
	@echo ""
	$(H) '$$ make test-unit' '# run main-module unit tests (cmd/pkg/signatures)'
	$(H) '$$ make test-unit PKG=pkg/path' '# run tests for specific package'
	$(H) '$$ make test-unit TEST=TestName' '# run specific test in all packages'
	$(H) '$$ make test-unit PKG=pkg/path TEST=TestName' '# run specific test in specific package'
	$(H) '$$ make test-types' '# run unit tests for types module'
	$(H) '$$ make test-common' '# run unit tests for common module'
	$(H) '$$ make test-detectors' '# run unit tests for detectors module'
	$(H) '$$ make test-api' '# run unit tests for api module'
	$(H) '$$ make test-traceectl' '# run unit tests for traceectl module'
	$(H) '$$ make test-common-extended' '# run unit tests for common-extended module (extended repo)'
	$(H) '$$ make test-integration' '# run integration tests (requires root)'
	$(H) '$$ make test-compatibility' '# run compatibility and fallback feature tests (requires root)'
	$(H) '$$ make test-e2e' '# run E2E core tests (requires root)'
	$(H) '$$ make test-e2e-net' '# run E2E network tests (requires root)'
	$(H) '$$ make test-e2e-kernel' '# run E2E kernel tests (requires root)'
	$(H) '$$ make test-e2e-vm' '# run kernel-tampering E2E tests in a Firecracker microVM (x86_64, needs /dev/kvm)'
	$(H) '$$ make test-e2e E2E_ARGS="--keep-artifacts"' '# pass flags to E2E scripts (kept artifacts land in /tmp/tracee on the host)'
	$(H) '$$ make test-performance' '# run performance/benchmark tests (requires root)'
	$(H) '$$ make test-upstream-libbpfgo' '# build+test against upstream libbpfgo main (requires root)'
	$(H) '$$ make run-scripts-test-unit' '# run the shell-script unit tests'
	$(H) '$$ make tests-submodules' '# run unit tests for the Go submodules (types, common, detectors, api, traceectl, common-extended)'
	$(H) '$$ make tests-unit' '# run ALL unit tests: main module + every submodule (no privilege)'
	$(H) '$$ make tests-e2e' '# run the whole E2E family (core + net + kernel + microVM) in one privileged run - ONE sudo prompt'
	$(H) '$$ make tests' '# run EVERY suite (unit + integration + e2e + microVM) in one privileged run - ONE sudo prompt'
	$(H) '$$ make coverage' '# print unit-test coverage summary'
	$(H) '$$ make coverage-html' '# generate an HTML unit-test coverage report'
	$(H) '$$ make fix-cache-perms' '# reclaim caches/artifacts left root-owned by earlier sudo test runs'
	@echo ""
	@echo "# development"
	@echo ""
	$(H) '$$ make bear' '# generate compile_commands.json (host paths, for clangd)'
	$(H) '$$ make man' '# generate man pages (pandoc container)'
	$(H) '$$ make protoc' '# regenerate protobuf code (protoc container)'
	$(H) '$$ make k8s-manifests' '# generate k8s manifests (controller-gen container)'
	$(H) '$$ make k8s-generate' '# generate k8s deepcopy code (controller-gen container)'
	$(H) '$$ make go-tidy' '# run go mod tidy across all modules'
	$(H) '$$ make go-get ARG="pkg@ver"' '# add/update a Go dependency'
	$(H) '$$ make mkdocs-build' '# build the docs site (mkdocs container)'
	$(H) '$$ make mkdocs-serve' '# serve the docs site at localhost:8000'
	$(H) '$$ make check-pr' '# comprehensive PR checks (code, tests)'
	$(H) '$$ make check-pr-fast' '# quick PR checks (skip static analysis + unit tests)'
	$(H) '$$ make check-pr-skip-tests' '# PR checks without unit tests'
	$(H) '$$ make format-pr' '# print formatted text for PR'
	$(H) '$$ make fix-fmt' '# fix formatting'
	@echo ""
	@echo "# performance testing"
	@echo ""
	$(H) '$$ make evt' '# build evt binary for stress testing'
	$(H) '$$ make evt-trigger-runner' '# build evt stress image (EVT_TRIGGER_RUNNER_IMAGE=... overrides)'
	$(H) '$$ make clean-evt-trigger-runner' '# clean evt trigger runner container'
	@echo ""
	@echo "# flags"
	@echo ""
	$(H) '$$ STATIC=1 make ...' '# build static binaries'
	$(H) '$$ BTFHUB=1 STATIC=1 make ...' '# build static binaries, embed BTF'
	$(H) '$$ DEBUG=1 make ...' '# build binaries with debug symbols'
	$(H) '$$ METRICS=1 make ...' '# build enabling BPF metrics'
	$(H) '$$ FIPS=1 make ...' '# build FIPS 140-3 compliant binaries'
	@echo ""
