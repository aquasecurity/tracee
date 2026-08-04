#!/usr/bin/env bash
#
# Run the kernel-tampering E2E core tests (default FTRACE_HOOK, HOOKED_SYSCALL)
# inside a throwaway Firecracker microVM, so the module insmod/rmmod and the
# host dmesg reads happen in an ephemeral kernel instead of the developer's or
# CI runner's live kernel.
#
# The microVM boots the HOST's CURRENTLY-RUNNING kernel (extracted from
# /boot/vmlinuz-$(uname -r)) - not a pinned download. Firecracker only buys
# isolation here; kernel *diversity* still comes from the CI AMI matrix, and
# booting the running kernel means each host (an AMI, or a dev laptop) exercises
# exactly the kernel it already runs, just sandboxed. That is what lets these
# tests run locally at all.
#
# Runs INSIDE the privileged ubuntu-fc build environment, which carries
# firecracker + the ext4/rsync tooling and has the host's kernel image, modules
# and build headers bind-mounted in (see mk/dispatch.mk FC_HOST_KERNEL_MOUNTS).
#
#   INSTTESTS           test selection passed to run.sh (default the 2 module tests)
#   FC_VCPUS / FC_MEM   guest sizing (default 2 / 2048)
#
# Mechanism: assemble an ext4 rootfs from THIS container's userland
# (rsync --one-file-system skips /proc /sys /dev and bind mounts), overlay the
# host kernel's modules+headers and a repo subset, drop a guest init that runs
# the tests and writes an rc sentinel, boot Firecracker, then read the sentinel
# back with debugfs (no loop-mount needed - container-friendly).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTTESTS="${INSTTESTS:-FTRACE_HOOK HOOKED_SYSCALL}"
FC_VCPUS="${FC_VCPUS:-2}"
FC_MEM="${FC_MEM:-2048}"

info() { echo "[e2e-vm] $*"; }
die() {
    echo "[e2e-vm] ERROR: $*" >&2
    exit 1
}
# a host whose running kernel genuinely cannot boot Firecracker (or would
# refuse the unsigned module) is not a failure - skip clearly and succeed, the
# same way the arch guard does. The CI AMIs (Ubuntu generic) never hit this.
skip_exit() {
    echo "[e2e-vm] SKIP: $*"
    exit 0
}

[ "$(uname -m)" = "x86_64" ] || die "the module e2e tests are x86_64-only"
[ "$(id -u)" -eq 0 ] || die "must run as root (privileged build environment)"
[ -c /dev/kvm ] || die "/dev/kvm not available - need a KVM-capable host"
command -v firecracker > /dev/null || die "firecracker not installed (ubuntu-fc image)"
command -v mkfs.ext4 > /dev/null || die "mkfs.ext4 not found (e2fsprogs)"
command -v debugfs > /dev/null || die "debugfs not found (e2fsprogs)"
command -v rsync > /dev/null || die "rsync not found"

# the running kernel (a container shares the host kernel, so uname -r here IS
# the host's); its image, config, modules and headers are bind-mounted in
KREL="$(uname -r)"
vmlinuz="/boot/vmlinuz-${KREL}"
kcfg="/boot/config-${KREL}"
kmoddir="/lib/modules/${KREL}"

[ -r "${vmlinuz}" ] || skip_exit "host kernel image ${vmlinuz} not available in the container - cannot boot the running kernel"
[ -d "${kmoddir}" ] || skip_exit "host kernel modules ${kmoddir} not mounted - cannot build the test module"
kbuild="$(readlink -f "${kmoddir}/build" 2> /dev/null || true)"
[ -n "${kbuild}" ] && [ -d "${kbuild}" ] || skip_exit "kernel build headers (${kmoddir}/build) not available - install kernel-devel/linux-headers for ${KREL}"

# 0. is the running kernel Firecracker-bootable and will it take an unsigned
#    module? Decide the virtio transport from its config.
FC_TRANSPORT=pci
if [ -r "${kcfg}" ]; then
    kon() { grep -q "^$1=y" "${kcfg}"; }
    for f in CONFIG_MODULES CONFIG_MODULE_UNLOAD CONFIG_KPROBES CONFIG_KALLSYMS_ALL \
        CONFIG_FUNCTION_TRACER CONFIG_DYNAMIC_FTRACE CONFIG_UPROBES CONFIG_VIRTIO_BLK; do
        kon "${f}" || skip_exit "running kernel lacks ${f}=y - cannot run the tampering tests in a microVM"
    done
    grep -q "^CONFIG_MODULE_SIG_FORCE=y" "${kcfg}" &&
        skip_exit "running kernel forces module signatures (MODULE_SIG_FORCE=y) - the unsigned test module would be rejected"
    # Firecracker presents the root disk over virtio-mmio classically; newer
    # versions can put it on a PCI bus (enable_pci). Prefer whichever the
    # running kernel has built in - Ubuntu generic has MMIO=y, Fedora ships
    # VIRTIO_MMIO=m but VIRTIO_PCI=y.
    if kon CONFIG_VIRTIO_MMIO; then
        FC_TRANSPORT=mmio
    elif kon CONFIG_VIRTIO_PCI; then
        FC_TRANSPORT=pci
    else
        skip_exit "running kernel has neither VIRTIO_MMIO=y nor VIRTIO_PCI=y built in - Firecracker could not expose the root disk"
    fi
else
    info "warning: ${kcfg} unreadable; assuming PCI transport and proceeding"
fi

work="$(mktemp -d /tmp/e2e-fc.XXXXXX)"
stage="${work}/rootfs"
rootfs="${work}/rootfs.ext4"
serial="${work}/serial.log"
trap 'rm -rf "${work}"' EXIT

info "kernel ${KREL} (${FC_TRANSPORT} transport); tests: ${INSTTESTS}"

# 1. uncompressed vmlinux (Firecracker needs an ELF, not the bzImage). Cache it
#    in the host-bind-mounted /tmp/tracee, keyed by version+size, so repeated
#    runs skip the decompress.
cache_dir="${FC_CACHE_DIR:-/tmp/tracee/.fc-cache}"
VMLINUX="${cache_dir}/vmlinux-${KREL}-$(stat -c %s "${vmlinuz}")"
if [ ! -s "${VMLINUX}" ]; then
    info "extracting vmlinux from ${vmlinuz}..."
    mkdir -p "${cache_dir}"
    "${SCRIPT_DIR}/installation/extract-vmlinux.sh" "${vmlinuz}" > "${VMLINUX}.part" ||
        { rm -f "${VMLINUX}.part"; die "could not extract an ELF vmlinux from ${vmlinuz}"; }
    mv -f "${VMLINUX}.part" "${VMLINUX}"
fi

# 2. base userland = this container's rootfs (skip virtual fs and bind mounts
#    via --one-file-system; drop caches to keep it lean).
#
#    CRITICAL: exclude /tmp/*. The staging dir lives under /tmp on the same
#    filesystem as /, so without this rsync copies its own (growing) output
#    back into itself and never terminates. The guest gets a fresh empty /tmp.
info "assembling rootfs staging from the build environment userland..."
mkdir -p "${stage}"
rsync -a --one-file-system \
    --exclude '/tmp/*' \
    --exclude '/var/cache/*' \
    --exclude '/root/go' \
    --exclude '/root/.cache' \
    --exclude '/home/*/go' \
    / "${stage}/" 2> /dev/null || true
mkdir -p "${stage}/proc" "${stage}/sys" "${stage}/dev" "${stage}/tracee" "${stage}/run"
mkdir -p "${stage}/tmp" && chmod 1777 "${stage}/tmp"

# 3. overlay the HOST kernel's modules metadata + build headers so out-of-tree
#    kbuild works in the guest and the /lib/modules/<ver>/build symlink stays
#    valid. Skip the bulky prebuilt .ko blobs under kernel/: the tests only
#    build and insmod their own module and load no others.
info "overlaying host kernel modules + build headers (${KREL})..."
mkdir -p "${stage}${kmoddir}"
cp -a "${kmoddir}/build" "${stage}${kmoddir}/" 2> /dev/null || true # the symlink itself
for f in "${kmoddir}"/modules.*; do
    [ -e "${f}" ] && cp -a "${f}" "${stage}${kmoddir}/"
done
mkdir -p "${stage}$(dirname "${kbuild}")"
cp -a "${kbuild}" "${stage}$(dirname "${kbuild}")/" # the headers/build tree at its real path

# 4. the full repo working tree (minus .git). run.sh cds here and runs
#    `make tracee-e2e lsm-check` unconditionally, so the guest needs the COMPLETE
#    source - not just dist/: the libbpf rule (mk/tracee.mk) shells out to `git
#    submodule update` when 3rdparty/libbpf/src is absent, and the Go/BPF build
#    references cmd/, signatures/, pkg/, etc. The host already built the binaries
#    into dist/ (test-e2e-vm's prereqs) in the SAME build context the guest uses
#    (TRACEE_BUILDENV_DISTRO=ubuntu -> dist/.ctx/ubuntu), so with all sources,
#    dist/ and the stamps present at their host mtimes the in-guest make is a
#    no-op. That matters because the microVM has NO network: a real rebuild would
#    try to fetch Go modules and fail. .git (344M) is skipped - only the cosmetic
#    version string needs it.
info "copying repo working tree..."
rsync -a --exclude '/.git' "${REPO_DIR}/" "${stage}/tracee/"

# the host may have pre-built the test .ko with the running kernel's own
# toolchain (mk/dispatch.mk); an out-of-tree module build inside the guest fails
# when the guest userland's toolchain does not match the kernel (Ubuntu make 4.3
# vs a Fedora 4.4.1 kernel tree). If the .ko are present, tell the guest to use
# them instead of rebuilding.
PREBUILT_MODULE=0
if [ -f "${REPO_DIR}/tests/e2e/core/scripts/hooker/hooker.ko" ] ||
    [ -f "${REPO_DIR}/tests/e2e/core/scripts/hijack/hijack.ko" ]; then
    PREBUILT_MODULE=1
    info "host-prebuilt kernel test modules found - guest will reuse them"
fi

# 5. guest init: bring up the kernel-tampering preconditions, run the selected
#    tests natively (TRACEE_BUILDENV=1 so the in-guest make does NOT dispatch
#    into a container), record the rc, and power off.
cat > "${stage}/usr/local/sbin/e2e-init" << INIT
#!/bin/bash
# /e2e-out is a REAL directory on the ext4 rootfs. Everything the host reads
# back with debugfs after poweroff (the rc sentinel, logs) must land here - NOT
# under /run or any tmpfs, which is gone the moment the VM stops.
mkdir -p /e2e-out

# stop the microVM so Firecracker exits. This build-env rootfs ships no
# poweroff/halt/reboot binary, so use the kernel's SysRq. Use 'b' (REBOOT), not
# 'o' (poweroff): with reboot=k the guest resets via the 8042 controller, which
# Firecracker treats as shutdown and exits. SysRq 'o' needs an ACPI/pm_power_off
# handler Firecracker's board does not provide, so it HALTS the CPU without ever
# exiting Firecracker (the run then hangs). rc + logs are synced first, and it
# is a throwaway rootfs, so a hard reset loses nothing. If SysRq is somehow off,
# returning from init makes PID1 exit -> panic=1 -> reboot -> exit anyway.
poweroff_vm() {
    sync
    sleep 1   # let the serial FIFO drain before the reset truncates output
    echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
    echo b > /proc/sysrq-trigger 2>/dev/null || true
    sleep 5
}

echo "[guest] e2e-init started; kernel \$(uname -r)"
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
ip link set lo up 2>/dev/null || true
sysctl -w kernel.kptr_restrict=0 kernel.dmesg_restrict=0 >/dev/null 2>&1 || true
# a freshly-booted init inherits a tiny RLIMIT_NOFILE (1024); kbuild + modpost
# against the full header tree blow past it ("Too many open files" building the
# test module). We are root/PID1, so raise it.
ulimit -n 1048576 2>/dev/null || ulimit -n 65536 2>/dev/null || true
echo "[guest] nofile limit: \$(ulimit -n)"

export TRACEE_BUILDENV=1 TRACEE_BUILDENV_DISTRO=ubuntu HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export E2E_PREBUILT_MODULE=${PREBUILT_MODULE}
if ! cd /tracee; then
    echo "[guest] ERROR: /tracee is missing or not a directory in the rootfs"
    ls -la / > /e2e-out/root-ls.txt 2>&1
    echo 255 > /e2e-out/e2e-rc
    poweroff_vm
fi

echo "[guest] running: ${INSTTESTS}"
INSTTESTS="${INSTTESTS}" ./tests/e2e/run.sh --keep-artifacts 2>&1 | tee /e2e-out/run.log
rc=\${PIPESTATUS[0]}
echo "\${rc}" > /e2e-out/e2e-rc
echo "[guest] e2e rc=\${rc}"
# collect the tests' own artifacts (run.sh writes these under /tmp)
cp /tmp/tracee-log-* /tmp/tracee-output-* /tmp/e2e-*.log /e2e-out/ 2>/dev/null || true
poweroff_vm
INIT
chmod +x "${stage}/usr/local/sbin/e2e-init"

# 6. build the ext4 image from staging (no loop mount: mkfs.ext4 -d)
info "building ext4 rootfs image..."
size_kb=$(du -sk "${stage}" | cut -f1)
img_mb=$(((size_kb / 1024) * 3 / 2 + 512)) # 1.5x + headroom
mkfs.ext4 -q -F -L e2eroot -d "${stage}" "${rootfs}" "${img_mb}M"

# 7. Firecracker config (no network: the 2 module tests need none). The root
#    disk rides virtio-mmio by default; on a kernel that only has virtio built
#    for PCI we enable Firecracker's PCI bus and drop pci=off so it enumerates.
#    PCI is turned on by the --enable-pci CLI flag (v1.13.1) - it is NOT a
#    machine-config field, which accepts only vcpu_count/mem_size_mib/smt/
#    cpu_template/track_dirty_pages/huge_pages.
machine_cfg="\"vcpu_count\": ${FC_VCPUS}, \"mem_size_mib\": ${FC_MEM}"
if [ "${FC_TRANSPORT}" = "pci" ]; then
    fc_pci_flag="--enable-pci"
    pci_arg=""
else
    fc_pci_flag=""
    pci_arg="pci=off "
fi
cat > "${work}/fc.json" << FCJSON
{
  "boot-source": {
    "kernel_image_path": "${VMLINUX}",
    "boot_args": "console=ttyS0 reboot=k panic=1 ${pci_arg}i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda rw init=/usr/local/sbin/e2e-init"
  },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "${rootfs}", "is_root_device": true, "is_read_only": false }
  ],
  "machine-config": { ${machine_cfg} }
}
FCJSON

# 8. boot; Firecracker exits when the guest reboots (SysRq b + reboot=k) or
#    panics (panic=1). Firecracker's serial console must go to a FILE (or pty),
#    NOT a pipe - piping its stdout stalls VM startup. So redirect the console
#    to ${serial} and get live visibility by following that file in the
#    background (the tests take tens of seconds: tracee start, BPF load, the
#    fixed detection waits). A timeout guards against a guest that never exits.
info "booting Firecracker microVM (guest console streams below; ~1-2 min)..."
: > "${serial}"
(tail -n +1 -f "${serial}" 2> /dev/null | sed 's/^/[guest] /') &
tail_pid=$!
set +e
# stdin from /dev/null, NOT the container's -it TTY: under `timeout` Firecracker
# runs outside the TTY's foreground process group, so touching the TTY (tcsetattr
# to set up the serial console) raises SIGTTOU and stops it before the VM starts.
# The guest init is autonomous and needs no console input, so detaching stdin is
# free and removes the TTY interaction entirely.
timeout "${FC_TIMEOUT:-300}" \
    firecracker --no-api ${fc_pci_flag} --config-file "${work}/fc.json" \
    < /dev/null > "${serial}" 2>&1
fc_rc=$?
set -e
sleep 1 # let the follower flush the final lines before we kill it
kill "${tail_pid}" 2> /dev/null || true
wait "${tail_pid}" 2> /dev/null || true
[ "${fc_rc}" = "124" ] && info "WARNING: Firecracker hit the ${FC_TIMEOUT:-300}s timeout (guest did not reboot/exit)"

# 9. read the rc sentinel + guest logs back from the ext4 image (debugfs, no
#    mount). The guest wrote them to /e2e-out, a real dir on the disk. Extract
#    into /tmp/tracee: the privileged run bind-mounts it from the host, so
#    artifacts survive the container and CI can upload them.
artifacts_out="${E2E_ARTIFACTS_DIR:-/tmp/tracee}"
mkdir -p "${artifacts_out}"
# persist the serial log host-side too (the work dir is wiped on exit)
cp "${serial}" "${artifacts_out}/e2e-serial.log" 2> /dev/null || true
# clear any previous extraction first: debugfs rdump will not overwrite an
# existing tree, so a stale /e2e-out from an earlier run would mask this one's
rm -rf "${artifacts_out}/e2e-out"
debugfs -R "rdump /e2e-out ${artifacts_out}" "${rootfs}" > /dev/null 2>&1 || true

rc_str="$(debugfs -R 'cat /e2e-out/e2e-rc' "${rootfs}" 2> /dev/null | tr -dc '0-9')"
if [ -z "${rc_str}" ]; then
    die "no exit-code sentinel from guest (firecracker rc=${fc_rc}); see the serial log above and ${artifacts_out}/e2e-serial.log"
fi

info "microVM e2e finished with rc=${rc_str} (guest logs under ${artifacts_out}/e2e-out)"
exit "${rc_str}"
