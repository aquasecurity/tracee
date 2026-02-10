#!/bin/bash
#
# Run E2E Kernel Tests inside QEMU (using virtme-ng)
# Usage: ./e2e-kernel-test-qemu.sh [kernel-version] [arch]
# Example: ./e2e-kernel-test-qemu.sh v6.12 x86_64
#
# NOTE: Currently only x86_64 is supported for QEMU testing.
# aarch64 testing requires native arm64 runners (TCG emulation is too slow).
#

set -euo pipefail

# Inputs
KERNEL_VERSION=${1:-$(uname -r)}
ARCH=${2:-$(uname -m)}

# Map input architecture to QEMU architecture
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    QEMU_ARCH="aarch64"
    ARCH="arm64"
else
    QEMU_ARCH="x86_64"
    ARCH="amd64"
fi

echo "Configuration: Kernel=$KERNEL_VERSION, Arch=$ARCH, QEMU_ARCH=$QEMU_ARCH"

# Ensure ~/.local/bin is on PATH (pip user installs go there)
export PATH="$HOME/.local/bin:$PATH"

# Install virtme-ng (vng) — the modern, maintained fork
install_virtme_ng() {
    if command -v vng >/dev/null 2>&1; then
        echo "vng (virtme-ng) already available: $(vng --version 2>&1 || true)"
        return
    fi

    echo "Installing virtme-ng..."
    pip3 install virtme-ng

    if ! command -v vng >/dev/null 2>&1; then
        echo "Error: vng not found on PATH after installation"
        echo "PATH=$PATH"
        exit 1
    fi
    echo "virtme-ng installed: $(vng --version 2>&1 || true)"

    # Ensure virtme-ng cache directory exists (fixes QEMU mount error)
    mkdir -p "$HOME/.cache/virtme-ng"
}

install_virtme_ng

# Locate kernel image and release
if [[ "$KERNEL_VERSION" == v* ]]; then
    VERSION_NUM=${KERNEL_VERSION#v}
    KERNEL_RELEASE=$(ls /boot/vmlinuz* 2>/dev/null | grep "$VERSION_NUM" | sort -V | tail -n1 | sed 's/.*vmlinuz-//' || true)
else
    KERNEL_RELEASE=$KERNEL_VERSION
fi

if [ -z "${KERNEL_RELEASE:-}" ]; then
    echo "Error: Could not find installed kernel for version $KERNEL_VERSION"
    ls -l /boot/vmlinuz* 2>/dev/null || echo "No vmlinuz files in /boot"
    exit 1
fi

echo "Selected Kernel Release: $KERNEL_RELEASE"

KERNEL_IMG="/boot/vmlinuz-$KERNEL_RELEASE"

if [[ ! -f "$KERNEL_IMG" ]]; then
    echo "Error: Kernel image not found at $KERNEL_IMG"
    exit 1
fi

# /boot is root-owned — CI runner user cannot read vmlinuz directly.
# Copy the kernel to the workspace so QEMU can access it.
LOCAL_KERNEL="./vmlinuz-$KERNEL_RELEASE"
echo "Copying kernel to workspace for QEMU access..."
sudo cp "$KERNEL_IMG" "$LOCAL_KERNEL"
sudo chmod +r "$LOCAL_KERNEL"

echo "Kernel image ready at: $LOCAL_KERNEL"

# Make /boot/vmlinuz readable so vng can find it by release name
sudo chmod +r "$KERNEL_IMG" 2>/dev/null || true

# Prepare test command
CMD="$(pwd)/tests/e2e-kernel-test-qemu-exec.sh"
chmod +x "$CMD"

# Build vng command
VNG_ARGS=(
    vng
    -r "$KERNEL_RELEASE"
    --verbose
    --memory 4G
    --cpus 2
)

# Cross-architecture emulation check
if [[ "$QEMU_ARCH" != "$(uname -m)" ]]; then
    echo "ERROR: Cross-architecture emulation ($QEMU_ARCH on $(uname -m)) is not supported."
    echo "aarch64 kernel testing requires native arm64 runners."
    echo "TCG emulation is too slow (~50x slower) for running Tracee (eBPF, module loading, etc.)."
    exit 1
fi

# Native architecture - use host rootfs
VNG_ARGS+=(--exec "$CMD")

echo "Launching virtme-ng..."
echo "Running: ${VNG_ARGS[*]}"
"${VNG_ARGS[@]}"
