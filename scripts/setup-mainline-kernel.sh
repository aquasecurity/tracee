#!/bin/bash
#
# Setup Mainline Kernel (without affecting host boot)
# Usage: ./setup-mainline-kernel.sh <full_version_string>
# Example: ./setup-mainline-kernel.sh 6.12.0-061200.202411172030
# Or simplified: ./setup-mainline-kernel.sh v6.12.0
#

set -e

# Default to latest stable if not specified (placeholder logic)
KERNEL_VERSION=${1:-v6.12}

# Normalize version string (v6.12 -> 6.12)
VERSION_CLEAN=$(echo "$KERNEL_VERSION" | sed 's/^v//')

# Determine Ubuntu Mainline PPA base URL (heuristic)
# For v6.x, pattern is v6.x.y/
# For simple tags, e.g. v6.12 -> v6.12/
BASE_URL="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${VERSION_CLEAN}"

# Architecture
ARCH=$(dpkg --print-architecture)

echo "Setting up Mainline Kernel: $VERSION_CLEAN ($ARCH)"
echo "Base URL: $BASE_URL"

# Working directory
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"

# Download index to find package names
echo "Fetching package index..."
wget -q -O index.html "$BASE_URL/"

# Find relevant .deb files
# Needs: linux-headers-*-generic, linux-modules-*-generic, linux-image-unsigned-*-generic
# We need only modules and image for QEMU boot, headers for building if needed (Tracee builds against headers).
# So we need headers too.

PACKAGES=$(grep -o 'href="[^"]*"' index.html | cut -d'"' -f2 | grep "_${ARCH}.deb" | grep -E "linux-headers.*generic|linux-modules.*generic|linux-image.*generic")

# Also need linux-headers-all for some versions? Usually included in generic depend.
# But let's grab what we find.

if [ -z "$PACKAGES" ]; then
    echo "Error: No packages found for $VERSION_CLEAN at $BASE_URL"
    # Fallback search for header-all (often architecture independent)
    exit 1
fi

echo "Found packages:"
echo "$PACKAGES"

for pkg in $PACKAGES; do
    echo "Downloading $pkg..."
    wget -q -c "$BASE_URL/$pkg"
done

echo "Installing kernel packages..."
# Install using dpkg, ignore dependencies if possible (start with headers then image)
if ! sudo dpkg -i *.deb; then
    echo "Warning: dpkg complained about dependencies. Attempting fix..."
    sudo apt-get install -f -y || echo "Failed to fix dependencies (might be okay if not essential)"
fi

# Locate installed kernel version string
# Check /boot/
echo "Checking installed kernel files in /boot..."
ls -l /boot/vmlinuz*

# Extract version string from filename (e.g. vmlinuz-6.12.0-061200-generic)
INSTALLED_KERNEL=$(ls /boot/vmlinuz* | grep "$VERSION_CLEAN" | sort -V | tail -n1)
KERNEL_RELEASE=$(basename "$INSTALLED_KERNEL" | sed 's/vmlinuz-//')

echo "Detected installed kernel release: $KERNEL_RELEASE"

if [ -n "$GITHUB_ENV" ]; then
    echo "KERNEL_RELEASE=$KERNEL_RELEASE" >> "$GITHUB_ENV"
fi

# Cleanup
rm -rf "$WORK_DIR"
