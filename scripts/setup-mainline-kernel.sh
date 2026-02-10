#!/bin/bash
#
# Setup Mainline Kernel (without affecting host boot)
# Usage: ./setup-mainline-kernel.sh <version> [--arch <arch>]
# Example: ./setup-mainline-kernel.sh v6.12 --arch arm64
#

set -euo pipefail

# Parse args
KERNEL_VERSION=""
ARCH=$(dpkg --print-architecture)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        *)
            if [ -z "$KERNEL_VERSION" ]; then
                KERNEL_VERSION="$1"
                shift
            else
                echo "Unknown argument: $1"
                exit 1
            fi
            ;;
    esac
done

if [ -z "$KERNEL_VERSION" ]; then
    echo "Usage: $0 <version> [--arch <arch>]"
    exit 1
fi

# Normalize Arch (amd64/x86_64 -> amd64, arm64/aarch64 -> arm64)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# Normalize Version
# v6.12 -> 6.12
VERSION_CLEAN=$(echo "$KERNEL_VERSION" | sed 's/^v//')

# Determine Ubuntu Mainline PPA base URL (heuristic)
# For v6.x, pattern is v6.x.y/
BASE_URL="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${VERSION_CLEAN}"

echo "Setting up Mainline Kernel $VERSION_CLEAN for $ARCH..."
echo "Base URL: $BASE_URL"

WORK_DIR=$(mktemp -d)
# Ensure cleanup on exit (success or failure)
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"

# Download index
echo "Fetching package index..."
if ! wget -q -O index.html "$BASE_URL/"; then
    echo "Error: Failed to fetch index from $BASE_URL/"
    exit 1
fi

# Find relevant .deb files
# Needs: linux-headers-*-generic, linux-modules-*-generic, linux-image-unsigned-*-generic
# or linux-image-*-generic if unsigned not present.
# We need BOTH arch-specific (_${ARCH}.deb) AND arch-independent (_all.deb) packages.
# The _all.deb packages contain shared headers required by the arch-specific headers.

ARCH_PACKAGES=$(grep -o 'href="[^"]*"' index.html | cut -d'"' -f2 | grep "_${ARCH}.deb" | grep -E "linux-headers.*generic|linux-modules.*generic|linux-image.*generic" || true)

ALL_PACKAGES=$(grep -o 'href="[^"]*"' index.html | cut -d'"' -f2 | grep "_all.deb" | grep -E "linux-headers" || true)

PACKAGES="$ARCH_PACKAGES"
if [ -n "$ALL_PACKAGES" ]; then
    PACKAGES="$PACKAGES $ALL_PACKAGES"
fi

# Trim whitespace
PACKAGES=$(echo "$PACKAGES" | xargs)

if [ -z "$PACKAGES" ]; then
    echo "Error: No packages found for $VERSION_CLEAN ($ARCH) at $BASE_URL"
    exit 1
fi

echo "Found packages:"
echo "$PACKAGES"

for pkg in $PACKAGES; do
    echo "Downloading $pkg..."
    wget -q -c "$BASE_URL/$pkg"
done

echo "Installing kernel packages..."

HOST_ARCH=$(dpkg --print-architecture)

if [[ "$HOST_ARCH" != "$ARCH" ]]; then
    echo "Cross-architecture install detected ($HOST_ARCH != $ARCH). Extracting packages instead of installing..."
    for deb in *.deb; do
        dpkg -x "$deb" extracted
    done

    echo "Moving extracted files to /boot..."
    sudo cp -rn extracted/boot/* /boot/ || echo "Warning: copy failed or files exist"

    # We also need modules in /lib/modules
    if [ -d extracted/lib/modules ]; then
        echo "Moving modules to /lib/modules..."
        sudo cp -rn extracted/lib/modules/* /lib/modules/ || echo "Warning: copy failed or modules exist"
    fi

    rm -rf extracted
else
    # Same arch, just install
    if ! sudo dpkg -i *.deb; then
        echo "Warning: dpkg complained about dependencies. Attempting fix..."
        sudo apt-get install -f -y || echo "Failed to fix dependencies (might be okay if not essential)"
    fi
fi

# Locate installed files
echo "Checking installed kernel files in /boot..."
INSTALLED_KERNEL=$(ls /boot/vmlinuz* 2>/dev/null | grep "$VERSION_CLEAN" | grep -v "old" | sort -V | tail -n1 || true)

if [ -z "$INSTALLED_KERNEL" ]; then
    echo "Error: Could not find vmlinuz for $VERSION_CLEAN in /boot"
    echo "Available kernels:"
    ls -l /boot/vmlinuz* 2>/dev/null || echo "  (none)"
    exit 1
fi

KERNEL_RELEASE=$(basename "$INSTALLED_KERNEL" | sed 's/vmlinuz-//')
echo "Detected installed kernel release: $KERNEL_RELEASE"

if [ -z "$KERNEL_RELEASE" ]; then
    echo "Error: Failed to determine kernel release from $INSTALLED_KERNEL"
    exit 1
fi

if [ -n "${GITHUB_ENV:-}" ]; then
    echo "KERNEL_RELEASE=$KERNEL_RELEASE" >> "$GITHUB_ENV"
fi

exit 0
