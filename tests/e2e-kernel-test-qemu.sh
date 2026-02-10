#!/bin/bash
#
# Run E2E Kernel Tests inside QEMU (using virtme-ng)
# Usage: ./e2e-kernel-test-qemu.sh [kernel-version]
# Example: ./e2e-kernel-test-qemu.sh v6.12.0
#

set -e

# Kernel version to test (default to current running kernel if not provided, though typically provided)
KERNEL_VERSION=${1:-$(uname -r)}

# Check for virtme-ng
if ! command -v vng >/dev/null; then
    echo "Installing virtme-ng..."
    sudo apt-get update && sudo apt-get install -y python3-pip qemu-system-x86
    pip3 install virtme-ng
fi

# Locate kernel image
if [[ "$KERNEL_VERSION" == v* ]]; then
    # Helper to find installed kernel by version string (e.g. v6.12 -> 6.12.0-061200-generic)
    # This assumes setup-mainline-kernel.sh ran previously
    KERNEL_RELEASE=$(ls /boot/vmlinuz* | grep "${KERNEL_VERSION#v}" | sort -V | tail -n1 | sed 's/.*vmlinuz-//')
else
    KERNEL_RELEASE=$KERNEL_VERSION
fi

if [ -z "$KERNEL_RELEASE" ]; then
    echo "Error: Could not find installed kernel for version $KERNEL_VERSION"
    exit 1
fi

echo "Running tests on Kernel: $KERNEL_RELEASE"

# Prepare command to run inside VM
# We assume the current directory is the root of the repo (mounted by virtme-ng)
# We need to install dependencies inside the VM if needed, or rely on host environment being passed through?
# virtme-ng shares the host filesystem by default in --rw mode usually, or specific mounts.
# But for compiling, we might need build tools.
# The `e2e-kernel-test.sh` script assumes tracee is already built on the host?
# "make -j$(nproc) all" is called inside `e2e-kernel-test.sh`.
# So the VM needs build tools (gcc, make, clang, libbpf headers).
# Since virtme-ng uses the host's rootfs (read-only overlay), the tools installed on host are available!

# Command to run inside VM
# We need to run as root.
# We mount the current directory to /tracee and run the test script.

CMD="./tests/e2e-kernel-test.sh"

echo "Launching virtme-ng..."

# --verbose for debugging
# --rw to allow writing to the mounted directory (for build artifacts)
# --pwd to start in current directory
# --cpus 2 --memory 4G
# script to run

vng --verbose --rw --pwd \
    --kernel "/boot/vmlinuz-$KERNEL_RELEASE" \
    --initrd "/boot/initrd.img-$KERNEL_RELEASE" \
    --cpus 2 --memory 4G \
    -- \
    "$CMD"
