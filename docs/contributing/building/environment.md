# The containerized building environment

> These instructions describe the containerized build environment that the
> main Makefile drives by default. If you would like to build tracee
> container(s) image(s), [read this](./containers.md) instead.

!!! Note
    Every `make` target runs inside a build container by default, containing
    all needed tools to build and test tracee. The only host requirements
    are `git`, `make` and a container engine: **docker** or **podman**
    (rootless podman works for building and all unprivileged targets; the
    privileged test targets run the engine with `sudo` automatically).

!!! Attention
    If you want to build tracee with your host's own toolchain instead,
    [read this](./building.md).

## Quick steps

1. Build and execute tracee (the build environment image is created
   automatically on first use):

    ```bash
    make tracee
    sudo ./dist/tracee \
        --enrichment decoded-data \
        --scope comm=bash \
        --scope follow
    ```

Now, in your host's shell, execute a command. You will see all events
(except scheduler ones) being printed, in "table format", to stdout.

## How it works

The root Makefile detects where it runs:

* On the **host**, it forwards the requested targets into the build
  environment container (one container run per invocation).
* **Inside the container** (or with `NATIVE=1`), the real build recipes run.

The build environment image (`tracee-buildenv:<distro>`) is rebuilt
automatically whenever `builder/Containerfile` or an installation script
changes - never on every run.

There are two maintained build environments:

* **Alpine** (default) - based on the [musl](https://en.wikipedia.org/wiki/Musl)
  C standard library; use `STATIC=1` for portable static binaries.
* **Ubuntu** - based on [glibc](https://en.wikipedia.org/wiki/Glibc).

By supporting both building environments we can always be sure that the
project builds (and executes) correctly in both environments.

!!! Attention
    The build containers share the host source code directory. If you build
    a dynamically linked tracee binary using the `alpine` environment, the
    binary might not be compatible with your host OS (see `STATIC=1` below).

## Which image serves which target

All images build from `builder/Containerfile` stages, are **local only**
(never pushed), and rebuild automatically when the Containerfile or an
installation script changes:

| Image | Stage | Targets |
|---|---|---|
| `tracee-buildenv:alpine` (default) / `:ubuntu` | `alpine-dev` / `ubuntu-dev` | builds, checks, unit tests, `bear`, all `test-*` (integration defaults to `:ubuntu`), `run*`, `shell`, the dev box, `lsp-*` |
| `tracee-buildenv:ubuntu-fc` | `ubuntu-fc` | `test-e2e-vm`, `image-fc` (adds Firecracker + QEMU + ext4/rsync tooling on top of `:ubuntu`; boots the host's running kernel, no kernel bundled; opt-in, kept off the default dev images) |
| `tracee-man:latest` | `man` | `man` |
| `tracee-protoc:latest` | `protoc` | `protoc` |
| `tracee-k8s:latest` | `k8s` | `k8s-manifests`, `k8s-generate` |
| `tracee-mkdocs:latest` | `mkdocs` | `mkdocs-build`, `mkdocs-serve` |
| `evt-trigger-runner:latest` | `evt-trigger-runner` | built by `evt-trigger-runner`, used at runtime by `evt stress` |
| `tracee-test:<rootfs>` | `distro-test` | `image-distro-test` (distro test matrix; runs the static tracee bind-mounted at run time) |

The **official (pushed) container image** `tracee:latest`/`tracee:dev` is
separate by design: it builds from `builder/Containerfile.release` via
`make -f builder/Makefile.tracee-container build-tracee` and the release
flow in `builder/Makefile.release` (see [containers.md](./containers.md)).

## Privileged vs unprivileged targets

No target needs `sudo` except the ones that load eBPF into the host kernel.
The unprivileged set - builds (`tracee`, `bpf`, `all`, ...), checks
(`check-fmt`, `check-lint`, `check-code`, ...), unit tests (`test-unit`,
`test-types`, `test-common`), codegen (`man`, `protoc`, `k8s-*`), docs
(`mkdocs-*`) and the image lifecycle targets - always produces host-owned
artifacts:

* **docker**: the container runs as the uid-matched `tracee` user (the
  daemon itself is root by docker's architecture, but nothing prompts).
* **rootless podman**: fully rootless; the container runs as
  container-root, which the user namespace maps to the invoking user - so
  root-gated unit tests execute while files stay yours.

The exceptions are the targets that load eBPF into the **host kernel**,
which is a real root requirement:

* `test-integration`, `test-compatibility`, `test-performance`
* `test-e2e`, `test-e2e-net`, `test-e2e-kernel`, `test-e2e-vm`, `test-upstream-libbpfgo`
* `tests` (the run-everything aggregate)
* `run` (executes the built tracee)
* `shell` (interactive, gets the same privileged profile)

`make tests` runs the whole suite - unit, integration, compatibility, the E2E
family, and the kernel-tampering VM tests (`test-e2e-vm`, last) - in a
**single** privileged container, so the engine escalates with `sudo` exactly
once and every suite then runs inside that one root container without
re-prompting. It continues past a failing suite and exits non-zero if any
failed. `make tests-unit` runs just the unit tests (no privilege).

These use a privileged container running as real root, and hand ownership
of `./dist` and coverage files back to the invoking user when the run ends.
Engine specifics:

* **docker**: the daemon is already root - no prompt appears at all, and
  the docker socket the tests use is inherently rootful.
* **rootless podman**: make announces and escalates the container run with
  `sudo` (images are still BUILT rootless and only transferred to the
  rootful store), and transiently starts the rootful podman API socket so
  containers the tests spawn execute as real uid 0.

## Kernel-tampering tests run in a VM

Two E2E core tests genuinely mutate kernel state - `FTRACE_HOOK` and
`HOOKED_SYSCALL` build a real kernel module, `insmod` it (one overwrites the
syscall table system-wide), and read host `dmesg`. Because containers share
the host kernel, `make test-e2e` self-skips those two on a developer or CI
box; they run for real only inside a throwaway **VM** via:

```bash
make test-e2e-vm                        # both module tests (x86_64)
INSTTESTS='FTRACE_HOOK' make test-e2e-vm  # select a subset
```

The VM boots the **host's currently-running kernel** - not a pinned download.
The VM only provides isolation here; kernel *diversity* still comes from the CI
AMI matrix, and booting the running kernel means each host (a CI AMI, or your
laptop) exercises exactly the kernel it already runs, just sandboxed. Two
backends are selected at run time (override with `E2E_VMM=firecracker|qemu`):
**Firecracker** when the host exposes `/dev/kvm` (fast), else a **QEMU + TCG**
software-emulation fallback that needs no KVM (slower, but the tests still run
instead of skipping - e.g. on non-bare-metal cloud instances, where AWS only
exposes `/dev/kvm` on `*.metal`). `scripts/e2e-firecracker.sh` assembles an
ephemeral ext4 rootfs from the `ubuntu-fc` image (`make image-fc` - Firecracker
+ QEMU plus ext4/rsync tooling) overlaid with the host kernel's modules and
build headers, the built `tracee-e2e`/`lsm-check`, and the repo's e2e subset,
boots the VM, runs `tests/e2e/run.sh` inside it, and reads the exit code back
out - so a mistaken module or a leaked `rmmod` never touches the host kernel.
(Firecracker needs an uncompressed `vmlinux`, extracted from
`/boot/vmlinuz-$(uname -r)` via `scripts/installation/extract-vmlinux.sh` and
cached under `/tmp/tracee/.fc-cache`; QEMU boots the `vmlinuz` directly.)

Under Firecracker the root disk rides virtio-mmio when the running kernel has
`VIRTIO_MMIO=y` (Ubuntu's generic kernel) or Firecracker's PCI bus
(`enable_pci`) when it only has `VIRTIO_PCI=y` (e.g. Fedora, where virtio-mmio
is a module); QEMU always uses virtio-blk over PCI (q35). x86_64 only (the
modules and the syscall-table hook are x86-specific); on aarch64, or on a host
whose running kernel cannot boot the VM or forces module signatures, the target
prints a skip notice and exits 0.

## Common operations

* Build any target in the (alpine) build environment:

    ```bash
    make tracee
    make bpf
    make test-unit
    make check-fmt
    ```

* Use the ubuntu (glibc) environment instead:

    ```bash
    make tracee DISTRO=ubuntu
    ```

* Open an interactive shell in the build environment (privileged by
  default, so tracee and the eBPF tests can run inside; `PRIV=0` gives an
  unprivileged shell for builds/checks/unit tests - no sudo involved, and
  targets needing root will skip or fail inside it):

    ```bash
    make shell                  # alpine, privileged
    make shell DISTRO=ubuntu    # ubuntu, privileged
    make shell PRIV=0           # unprivileged (no sudo)
    ```

* Manage the build environment images:

    ```bash
    make image                  # (re)build tracee-buildenv:alpine if stale
    make images                 # build all distros
    make image-fc               # build the VM-capable image for test-e2e-vm
    make clean-images           # remove the local images
    ```

* Pick the engine explicitly (auto-detection prefers docker, then podman):

    ```bash
    CONTAINER_ENGINE=podman make tracee
    ```

## Editing with the container's toolchain

Two tiers, so any editor works against the exact toolchain `make` builds
with:

* **Language server over stdio (the floor)** - `make lsp-go` (gopls) and
  `make lsp-c` (clangd) run the server from the buildenv image with the repo
  mounted at its host path, so the `file://` URIs match what your editor
  sees - no path translation, no daemon, keys, or ports. Point your editor's
  server command at the make target (`make lsp-print-go` / `lsp-print-c`
  print the raw argv for editors that must wrap the command). `make bear`
  generates a `compile_commands.json` with host paths for clangd. These
  targets never rebuild the image mid-session; run `make image` first.
* **Attach a full editor** - `make dev` starts a persistent box (repo at
  `/tracee`, home on a named volume so caches survive restarts); `make
  attach` prints the ways in: Emacs via TRAMP's podman method
  (`/podman:tracee-dev-box:/tracee/`), VS Code/Cursor via "Attach to Running
  Container" (or "Reopen in Container" with the shipped `.devcontainer`),
  anything else via `podman exec -it tracee-dev-box bash`. An sshd bound to
  `127.0.0.1:2222` is the optional extra for editors that only speak
  Remote-SSH (`make dev-ssh` opens a shell over it; `SSH_PORT` and
  `SSH_PUBKEY` override the defaults). `make dev-stop` removes the box,
  `make clean-dev` also removes its home volume.

Inside the box (or over its ssh), `make` runs the toolchain directly - no
nested containers. Run the engine-driving targets (`make dev`, `make image`,
`make shell`, the privileged tests) from the host.

One rootless-podman subtlety worth knowing: container-root maps to *you*, so
ordinary edits stay yours - but a file created through `sudo` inside the box
is owned by a **subuid**, not by you. Keep `sudo` for real root work
(package installs), and do ordinary edits as yourself.

## Building a portable (static) binary

If you don't want to depend on the host's library versions, set the `STATIC`
variable to `1` so compiled binaries run on any host machine:

1. Compile tracee

    ```bash
    STATIC=1 make all
    ```

2. Verify the executable is static

    * Note: ldd prints the shared libraries required by an executable file

    ```bash
    ldd dist/tracee
    ```

    ```text
    not a dynamic executable
    ```

3. Execute the static binary from your host

    ```bash
    sudo ./dist/tracee
    ```

## Deprecated: builder/Makefile.tracee-make

The previous entry points (`make -f builder/Makefile.tracee-make
alpine-prepare/alpine-shell/alpine-make ARG=...`) still work as deprecation
shims forwarding to the targets above, and will be removed in a future
release.
