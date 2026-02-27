#!/bin/bash
# Install specific kernel version (distro-agnostic)
# Usage: ./install-kernel.sh -d ubuntu -f generic -k 5.19.0-50
#        ./install-kernel.sh --distro auto --flavor generic --kernel-version 5.19.0-50

set -euo pipefail

# Function to show usage
usage() {
    cat << EOF
Usage: $0 -d DISTRO -f FLAVOR -k VERSION

Install a specific kernel version (distro-agnostic).

Required Arguments:
  -d, --distro DISTRO              Target distribution (ubuntu, centos, alpine, or auto for auto-detect)
  -f, --flavor FLAVOR              Kernel flavor (generic, aws, gcp, azure, mainline, lts, vanilla)
  -k, --kernel-version VERSION     Kernel version (e.g., 5.19.0-50)

Examples:
  $0 -d ubuntu -f generic -k 5.19.0-50
  $0 --distro auto --flavor generic --kernel-version 5.19.0-50
  $0 -d centos -f standard -k 5.15.0-1

Supported Distros:
  - ubuntu, debian    (flavors: generic, aws, gcp, azure, mainline)
  - centos, rhel      (flavors: generic, standard, mainline, elrepo)
  - alpine            (flavors: vanilla, lts)
  - auto              (auto-detect from /etc/os-release)

EOF
    exit 1
}

# Initialize variables
DISTRO=""
KERNEL_FLAVOR=""
KERNEL_VERSION=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--distro)
            DISTRO="$2"
            shift 2
            ;;
        -f|--flavor)
            KERNEL_FLAVOR="$2"
            shift 2
            ;;
        -k|--kernel-version)
            KERNEL_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$DISTRO" ] || [ -z "$KERNEL_FLAVOR" ] || [ -z "$KERNEL_VERSION" ]; then
    echo "Error: All arguments are required (-d, -f, -k)"
    echo ""
    usage
fi

echo "Installing kernel ${KERNEL_FLAVOR} ${KERNEL_VERSION} on ${DISTRO}..."

# Auto-detect distro if specified as "auto"
if [ "$DISTRO" = "auto" ]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian) DISTRO="ubuntu" ;;
            centos|rhel|rocky|almalinux) DISTRO="centos" ;;
            alpine) DISTRO="alpine" ;;
            *)
                echo "Error: Could not auto-detect distro from ID: $ID"
                exit 1
                ;;
        esac
        echo "Auto-detected distro: ${DISTRO}"
    else
        echo "Error: Cannot auto-detect distro (/etc/os-release not found)"
        exit 1
    fi
fi

# Install kernel based on distro
case "${DISTRO}" in
    ubuntu|debian)
        case "${KERNEL_FLAVOR}" in
            generic)
                apt-get update -y
                apt-get install -y \
                    "linux-image-${KERNEL_VERSION}-generic" \
                    "linux-headers-${KERNEL_VERSION}-generic" \
                    "linux-modules-extra-${KERNEL_VERSION}-generic" \
                    "linux-tools-${KERNEL_VERSION}-generic"
                ;;
            
            aws)
                apt-get update -y
                apt-get install -y \
                    "linux-image-${KERNEL_VERSION}" \
                    "linux-headers-${KERNEL_VERSION}" \
                    "linux-modules-extra-${KERNEL_VERSION}"
                ;;
            
            gcp)
                apt-get update -y
                apt-get install -y \
                    "linux-image-${KERNEL_VERSION}" \
                    "linux-headers-${KERNEL_VERSION}"
                ;;
            
            azure)
                apt-get update -y
                apt-get install -y \
                    "linux-image-${KERNEL_VERSION}" \
                    "linux-headers-${KERNEL_VERSION}"
                ;;
            
            mainline)
                apt-get update -y
                apt-get install -y software-properties-common
                add-apt-repository -y ppa:canonical-kernel-team/ppa || true
                apt-get update -y
                apt-get install -y \
                    "linux-image-unsigned-${KERNEL_VERSION}-generic" \
                    "linux-headers-${KERNEL_VERSION}-generic"
                ;;
            
            *)
                echo "Unknown kernel flavor for Ubuntu/Debian: ${KERNEL_FLAVOR}"
                exit 1
                ;;
        esac
        
        # Update GRUB
        update-grub
        ;;
    
    centos|rhel|rocky|almalinux)
        case "${KERNEL_FLAVOR}" in
            generic|standard)
                # Install from standard repos
                dnf install -y \
                    "kernel-${KERNEL_VERSION}" \
                    "kernel-headers-${KERNEL_VERSION}" \
                    "kernel-devel-${KERNEL_VERSION}" \
                    "kernel-tools-${KERNEL_VERSION}" || \
                yum install -y \
                    "kernel-${KERNEL_VERSION}" \
                    "kernel-headers-${KERNEL_VERSION}" \
                    "kernel-devel-${KERNEL_VERSION}" \
                    "kernel-tools-${KERNEL_VERSION}"
                ;;
            
            mainline|elrepo)
                # Install from ELRepo for newer kernels
                dnf install -y elrepo-release || yum install -y elrepo-release
                dnf --enablerepo=elrepo-kernel install -y \
                    "kernel-ml-${KERNEL_VERSION}" \
                    "kernel-ml-headers-${KERNEL_VERSION}" \
                    "kernel-ml-devel-${KERNEL_VERSION}" || \
                yum --enablerepo=elrepo-kernel install -y \
                    "kernel-ml-${KERNEL_VERSION}" \
                    "kernel-ml-headers-${KERNEL_VERSION}" \
                    "kernel-ml-devel-${KERNEL_VERSION}"
                ;;
            
            *)
                echo "Unknown kernel flavor for CentOS/RHEL: ${KERNEL_FLAVOR}"
                exit 1
                ;;
        esac
        
        # Update GRUB2
        grub2-mkconfig -o /boot/grub2/grub.cfg || grubby --set-default="/boot/vmlinuz-${KERNEL_VERSION}"
        ;;
    
    alpine)
        case "${KERNEL_FLAVOR}" in
            vanilla|standard)
                apk update
                apk add \
                    "linux-vanilla~=${KERNEL_VERSION%.*}" \
                    "linux-vanilla-dev~=${KERNEL_VERSION%.*}"
                ;;
            
            lts)
                apk update
                apk add \
                    "linux-lts~=${KERNEL_VERSION%.*}" \
                    "linux-lts-dev~=${KERNEL_VERSION%.*}"
                ;;
            
            *)
                echo "Unknown kernel flavor for Alpine: ${KERNEL_FLAVOR}"
                echo "Supported flavors: vanilla, lts"
                exit 1
                ;;
        esac
        
        # Update bootloader
        update-extlinux || true
        ;;
    
    *)
        echo "Unsupported distro: ${DISTRO}"
        echo "Supported distros: ubuntu, debian, centos, rhel, rocky, almalinux, alpine"
        exit 1
        ;;
esac

echo "Kernel ${KERNEL_FLAVOR} ${KERNEL_VERSION} installed successfully on ${DISTRO}"
