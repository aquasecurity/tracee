#!/bin/bash
# Generate cloud-init configuration from templates
# This script creates customized cloud-init files for VM provisioning

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
DISTRO=""
VERSION=""
KERNEL_FLAVOR=""
KERNEL_VERSION=""
ARCH=""
ENVIRONMENT=""
SSH_PUBKEY_FILE=""

# Usage function
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate cloud-init configuration files and ISO for VM provisioning.

OPTIONS:
    -d, --distro DISTRO              Distribution name (ubuntu, centos, alpine)
    -v, --distro-version VERSION     Distribution version (22.04, 24.04, 9, etc.)
    -f, --kernel-flavor FLAVOR       Kernel flavor (generic, aws, gcp, azure, mainline, vanilla, lts)
    -k, --kernel-version VERSION     Kernel version (5.19.0-50, 6.11.0-29, etc.)
    -a, --arch ARCH                  Architecture (x86_64, aarch64)
    -e, --env ENVIRONMENT            Environment type (local, aws)
    -s, --ssh-key FILE               SSH public key file to inject (default: ~/.ssh/tracee_team_ed25519.pub)
    -o, --output-dir DIR             Output directory (default: ${SCRIPT_DIR}/generated)
    -h, --help                       Show this help message

EXAMPLES:
    # Ubuntu 22.04 with generic kernel for local development
    $(basename "$0") -d ubuntu -v 22.04 -f generic -k 5.19.0-50 -a x86_64 -e local

    # Ubuntu 24.04 with AWS kernel for CI/CD
    $(basename "$0") --distro ubuntu --distro-version 24.04 --kernel-flavor aws \\
        --kernel-version 6.11.0-29 --arch x86_64 --env aws

    # CentOS Stream 9 for local development
    $(basename "$0") -d centos -v 9 -f generic -k 5.14.0-503 -a x86_64 -e local

    # Alpine 3.19 with vanilla kernel
    $(basename "$0") -d alpine -v 3.19 -f vanilla -k 6.6.0 -a x86_64 -e local

SUPPORTED DISTRIBUTIONS:
    ubuntu          Ubuntu/Debian (uses apt-get)
    centos          CentOS/RHEL/Rocky/AlmaLinux (uses dnf/yum)
    alpine          Alpine Linux (uses apk)

KERNEL FLAVORS BY DISTRO:
    Ubuntu/Debian:  generic, aws, gcp, azure, mainline
    CentOS/RHEL:    generic, standard, mainline, elrepo
    Alpine:         vanilla, lts

ENVIRONMENTS:
    local           Local development (includes mount points for shared directories)
    aws             AWS/CI/CD (optimized for GitHub Actions, no local mounts)

OUTPUT:
    Generated files are placed in: ${SCRIPT_DIR}/generated/
    - {image-name}-user-data.yaml    Cloud-init user data configuration
    - {image-name}-meta-data.yaml    Cloud-init metadata
    
    Next steps:
    1. cd ${SCRIPT_DIR}/generated/
    2. cloud-localds {image-name}-cloud-init.iso {image-name}-user-data.yaml {image-name}-meta-data.yaml
    3. Copy ISO to your VM directory
    4. Boot VM with the cloud-init ISO

NAMING CONVENTION:
    Generated files follow: {distro}-{version}-{flavor}-{kernel-version}-{arch}
    Example: ubuntu-22.04-generic-5.19.0-50-x86_64

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--distro)
            DISTRO="$2"
            shift 2
            ;;
        -v|--distro-version)
            VERSION="$2"
            shift 2
            ;;
        -f|--kernel-flavor)
            KERNEL_FLAVOR="$2"
            shift 2
            ;;
        -k|--kernel-version)
            KERNEL_VERSION="$2"
            shift 2
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -e|--env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -s|--ssh-key)
            SSH_PUBKEY_FILE="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR_ARG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$DISTRO" ]]; then
    echo "Error: --distro is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$VERSION" ]]; then
    echo "Error: --distro-version is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$KERNEL_FLAVOR" ]]; then
    echo "Error: --kernel-flavor is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$KERNEL_VERSION" ]]; then
    echo "Error: --kernel-version is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$ARCH" ]]; then
    echo "Error: --arch is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$ENVIRONMENT" ]]; then
    echo "Error: --env is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

# Validate distro
case "$DISTRO" in
    ubuntu|debian|centos|rhel|rocky|almalinux|alpine)
        ;;
    *)
        echo "Error: Unsupported distro: $DISTRO" >&2
        echo "Supported: ubuntu, debian, centos, rhel, rocky, almalinux, alpine" >&2
        exit 1
        ;;
esac

# Validate environment
case "$ENVIRONMENT" in
    local|aws)
        ;;
    *)
        echo "Error: Unsupported environment: $ENVIRONMENT" >&2
        echo "Supported: local, aws" >&2
        exit 1
        ;;
esac

# Validate architecture
case "$ARCH" in
    x86_64|aarch64|arm64)
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        echo "Supported: x86_64, aarch64, arm64" >&2
        exit 1
        ;;
esac

# Resolve SSH public key
if [[ -z "${SSH_PUBKEY_FILE}" ]]; then
    # Default: look for tracee team key, fall back to common keys
    for candidate in ~/.ssh/tracee_team_ed25519.pub ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub; do
        if [[ -f "${candidate}" ]]; then
            SSH_PUBKEY_FILE="${candidate}"
            break
        fi
    done
fi
if [[ -n "${SSH_PUBKEY_FILE}" ]] && [[ -f "${SSH_PUBKEY_FILE}" ]]; then
    SSH_PUBKEY=$(cat "${SSH_PUBKEY_FILE}")
    SSH_KEY_NAME=$(basename "${SSH_PUBKEY_FILE}" .pub)
else
    echo "Warning: No SSH public key found. VM will only be accessible via console password." >&2
    SSH_PUBKEY=""
    SSH_KEY_NAME="none"
fi

# Build image name (include environment so local and aws builds coexist)
IMAGE_NAME="${DISTRO}-${VERSION}-${KERNEL_FLAVOR}-${KERNEL_VERSION}-${ARCH}-${ENVIRONMENT}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Generating Cloud-Init Configuration                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Select template based on distro family
case "$DISTRO" in
    ubuntu|debian)
        USER_DATA_TEMPLATE_FILE="user-data-ubuntu-template.yaml"
        ;;
    centos|rhel|rocky|almalinux)
        USER_DATA_TEMPLATE_FILE="user-data-centos-template.yaml"
        ;;
    alpine)
        USER_DATA_TEMPLATE_FILE="user-data-alpine-template.yaml"
        ;;
    *)
        echo "Error: No template available for distro: $DISTRO" >&2
        echo "Available: ubuntu, debian, centos, rhel, rocky, almalinux, alpine" >&2
        exit 1
        ;;
esac

echo "Configuration:"
echo "  Distro:         ${DISTRO} ${VERSION}"
echo "  Kernel:         ${KERNEL_FLAVOR} ${KERNEL_VERSION}"
echo "  Architecture:   ${ARCH}"
echo "  Environment:    ${ENVIRONMENT}"
echo "  SSH Key:        ${SSH_KEY_NAME} (${SSH_PUBKEY_FILE:-none})"
echo "  Template:       ${USER_DATA_TEMPLATE_FILE}"
echo "  Image Name:     ${IMAGE_NAME}"
echo ""

# Read templates
if [[ ! -f "${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}" ]]; then
    echo "Error: Template file not found: ${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}" >&2
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/templates/meta-data-template.yaml" ]]; then
    echo "Error: Template file not found: ${SCRIPT_DIR}/templates/meta-data-template.yaml" >&2
    exit 1
fi

USER_DATA_TEMPLATE=$(cat "${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}")
META_DATA_TEMPLATE=$(cat "${SCRIPT_DIR}/templates/meta-data-template.yaml")

# Read step files (common sections)
# Step files are already properly indented for runcmd section
INIT_SERVICES=$(cat "${SCRIPT_DIR}/templates/steps/init-services.yaml")
DOWNLOAD_SCRIPTS=$(cat "${SCRIPT_DIR}/templates/steps/download-scripts.yaml")
DISABLE_UNATTENDED=$(cat "${SCRIPT_DIR}/templates/steps/ubuntu-disable-unattended-upgrades.yaml")
INSTALL_TOOLS=$(cat "${SCRIPT_DIR}/templates/steps/install-tools.yaml")
SETUP_VIRTFS=$(cat "${SCRIPT_DIR}/templates/steps/setup-virtfs.yaml")
FINALIZE=$(cat "${SCRIPT_DIR}/templates/steps/finalize.yaml")
WRITE_VM_CONFIGS=$(cat "${SCRIPT_DIR}/templates/steps/write-vm-configs.yaml")

# Embed locally-maintained scripts (these will eventually be fetched from the repo)
if [[ ! -f "${SCRIPT_DIR}/scripts/install-kernel.sh" ]]; then
    echo "Error: Kernel installation script not found: ${SCRIPT_DIR}/scripts/install-kernel.sh" >&2
    exit 1
fi
INSTALL_KERNEL=$(cat "${SCRIPT_DIR}/scripts/install-kernel.sh" | sed 's/^/    /')

if [[ ! -f "${SCRIPT_DIR}/scripts/setup-motd.sh" ]]; then
    echo "Error: MOTD setup script not found: ${SCRIPT_DIR}/scripts/setup-motd.sh" >&2
    exit 1
fi
SETUP_MOTD=$(cat "${SCRIPT_DIR}/scripts/setup-motd.sh" | sed 's/^/    /')

# Determine username based on distro
case "$DISTRO" in
    ubuntu|debian)
        USERNAME="ubuntu"
        ;;
    centos|rhel|rocky|almalinux)
        USERNAME="ec2-user"
        ;;
    alpine)
        USERNAME="alpine"
        ;;
    *)
        USERNAME="ubuntu"
        ;;
esac

# Build SSH access hint based on environment
if [[ "${SSH_KEY_NAME}" != "none" ]]; then
    SSH_KEY_FLAG="-i ~/.ssh/${SSH_KEY_NAME} "
else
    SSH_KEY_FLAG=""
fi
case "${ENVIRONMENT}" in
    aws)
        SSH_ACCESS_HINT="SSH Access (from your workstation):
    ssh ${SSH_KEY_FLAG}${USERNAME}@<instance-public-ip>"
        ;;
    *)
        SSH_ACCESS_HINT="SSH Access:
    ssh ${SSH_KEY_FLAG}-p 2222 ${USERNAME}@localhost"
        ;;
esac

# Replace variables in template
USER_DATA="${USER_DATA_TEMPLATE//\$\{DISTRO\}/${DISTRO}}"
USER_DATA="${USER_DATA//\$\{VERSION\}/${VERSION}}"
USER_DATA="${USER_DATA//\$\{KERNEL_FLAVOR\}/${KERNEL_FLAVOR}}"
USER_DATA="${USER_DATA//\$\{KERNEL_VERSION\}/${KERNEL_VERSION}}"
USER_DATA="${USER_DATA//\$\{ENVIRONMENT\}/${ENVIRONMENT}}"
USER_DATA="${USER_DATA//\$\{SSH_PUBKEY\}/${SSH_PUBKEY}}"
USER_DATA="${USER_DATA//\$\{SSH_KEY_NAME\}/${SSH_KEY_NAME}}"
USER_DATA="${USER_DATA//\$\{SSH_ACCESS_HINT\}/${SSH_ACCESS_HINT}}"

# Replace variables in step files
# Note: Most variables (DISTRO, VERSION, etc.) are now sourced from /tmp/tracee-vm-env.sh
# at runtime, so we only need to replace variables that aren't in the env file:
# - USERNAME: Not in env file, needs generation-time replacement
INIT_SERVICES="${INIT_SERVICES//\$\{USERNAME\}/${USERNAME}}"
SETUP_VIRTFS="${SETUP_VIRTFS//\$\{USERNAME\}/${USERNAME}}"

META_DATA="${META_DATA_TEMPLATE//\$\{DISTRO\}/${DISTRO}}"
META_DATA="${META_DATA//\$\{VERSION\}/${VERSION}}"
META_DATA="${META_DATA//\$\{KERNEL_FLAVOR\}/${KERNEL_FLAVOR}}"
META_DATA="${META_DATA//\$\{KERNEL_VERSION\}/${KERNEL_VERSION}}"
META_DATA="${META_DATA//\$\{ARCH\}/${ARCH}}"

# Replace placeholders with steps using awk for proper multiline handling
USER_DATA=$(echo "$USER_DATA" | awk -v init_svc="$INIT_SERVICES" -v download="$DOWNLOAD_SCRIPTS" -v disable_unattended="$DISABLE_UNATTENDED" -v tools="$INSTALL_TOOLS" -v virtfs="$SETUP_VIRTFS" -v finalize="$FINALIZE" -v kernel="$INSTALL_KERNEL" -v motd="$SETUP_MOTD" -v write_vm_configs="$WRITE_VM_CONFIGS" '
/^  # WRITE_VM_CONFIGS_PLACEHOLDER$/ {
    print write_vm_configs
    next
}
/^  # INIT_SERVICES_PLACEHOLDER$/ {
    print init_svc
    next
}
/^  # DOWNLOAD_SCRIPTS_PLACEHOLDER$/ {
    print download
    next
}
/^  # DISABLE_UNATTENDED_UPGRADES_PLACEHOLDER$/ {
    print disable_unattended
    next
}
/^  # INSTALL_TOOLS_PLACEHOLDER$/ {
    print tools
    next
}
/^  # SETUP_VIRTFS_PLACEHOLDER$/ {
    print virtfs
    next
}
/^  # FINALIZE_PLACEHOLDER$/ {
    print finalize
    next
}
/# MOTD_SCRIPT_PLACEHOLDER/ {
    print "    cat > /tmp/setup-motd.sh <<'"'"'MOTD_SCRIPT'"'"'"
    print motd
    print "    MOTD_SCRIPT"
    next
}
/# KERNEL_SCRIPT_PLACEHOLDER/ {
    print "  - |"
    print "    cat > /tmp/install-kernel.sh <<'"'"'KERNEL_SCRIPT'"'"'"
    print kernel
    print "    KERNEL_SCRIPT"
    next
}
{ print }
')

# Write output files
OUTPUT_DIR="${OUTPUT_DIR_ARG:-${SCRIPT_DIR}/generated}"
mkdir -p "${OUTPUT_DIR}"

echo "$USER_DATA" > "${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml"
echo "$META_DATA" > "${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"

echo "✓ Generated files:"
echo "  ${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml"
echo "  ${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"
echo ""
echo "Next steps:"
echo "  1. Create cloud-init ISO from the generated files:"
echo "     cloud-localds ${IMAGE_NAME}-cloud-init.iso \\"
echo "         ${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml \\"
echo "         ${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"
echo ""
echo "  2. Boot VM with the cloud-init ISO and base image"
echo ""
echo "Note: VM images are not included in the repository."
echo "      Download them separately or use the VM management scripts (coming soon)."
echo ""
