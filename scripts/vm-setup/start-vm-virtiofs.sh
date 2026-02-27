#!/bin/bash
# Start Tracee VM with virtiofs shared directories
#
# This script:
# 1. Detects target architecture from VM name
# 2. Starts virtiofsd daemons for host directory sharing (native arch only)
# 3. Launches QEMU with appropriate settings per architecture

set -e

# Configuration
VM_NAME="${1:-ubuntu-22.04-generic-5.19.0-50-x86_64}"
VM_DIR="${VM_DIR:-${HOME}/vms}"
TRACEE_DIR="${TRACEE_DIR:-${HOME}/code/tracee}"
VIRTIOFSD="${VIRTIOFSD:-/usr/libexec/virtiofsd}"

# VM resources
VM_RAM="${VM_RAM:-4G}"
VM_CPUS="${VM_CPUS:-4}"
SSH_PORT="${SSH_PORT:-2222}"

# Socket and log paths
TRACEE_SOCK="/tmp/vhost-tracee.sock"
VIRTIOFSD_LOG="/tmp/virtiofsd-tracee.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Starting Tracee VM with Virtiofs                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Detect target and host architecture early (before virtiofsd decision)
HOST_ARCH=$(uname -m)
TARGET_ARCH="x86_64"
if [[ "${VM_NAME}" == *-aarch64-* ]] || [[ "${VM_NAME}" == *-arm64-* ]]; then
    TARGET_ARCH="aarch64"
fi

# Determine if we can use KVM (same arch) or must fall back to TCG
USE_KVM=0
if [[ "${TARGET_ARCH}" == "${HOST_ARCH}" ]]; then
    USE_KVM=1
fi

# Virtiofs requires shared memory (memfd+numa) which only works reliably with KVM.
# For cross-arch TCG emulation, skip virtiofs — use SSH/scp for file transfer instead.
USE_VIRTIOFS=0
if [[ "${USE_KVM}" -eq 1 ]]; then
    USE_VIRTIOFS=1
fi

# Check if VM image exists (.qcow2 or .img)
VM_DISK=""
VM_FORMAT=""
if [ -f "${VM_DIR}/${VM_NAME}.qcow2" ]; then
    VM_DISK="${VM_DIR}/${VM_NAME}.qcow2"
    VM_FORMAT="qcow2"
elif [ -f "${VM_DIR}/${VM_NAME}.img" ]; then
    VM_DISK="${VM_DIR}/${VM_NAME}.img"
    if command -v qemu-img &>/dev/null; then
        VM_FORMAT=$(qemu-img info "${VM_DISK}" 2>/dev/null | awk '/^file format:/{print $3}')
    fi
    VM_FORMAT="${VM_FORMAT:-qcow2}"
else
    echo -e "${RED}Error: VM image not found: ${VM_DIR}/${VM_NAME}.qcow2 or ${VM_DIR}/${VM_NAME}.img${NC}"
    exit 1
fi

# QEMU needs write access to the disk image
if [ ! -w "${VM_DISK}" ]; then
    echo -e "${RED}Error: VM image is not writable: ${VM_DISK}${NC}"
    echo "QEMU needs write access. Fix with: chmod u+w ${VM_DISK}"
    exit 1
fi

# Check if cloud-init ISO exists
if [ ! -f "${VM_DIR}/${VM_NAME}-cloud-init.iso" ]; then
    echo -e "${YELLOW}Warning: cloud-init ISO not found: ${VM_DIR}/${VM_NAME}-cloud-init.iso${NC}"
    echo "VM will boot without cloud-init configuration"
fi

# Check if shared directories exist
if [ ! -d "${TRACEE_DIR}" ]; then
    echo -e "${RED}Error: Tracee directory not found: ${TRACEE_DIR}${NC}"
    exit 1
fi

# Clean up old sockets and logs
rm -f "${TRACEE_SOCK}"
rm -f "${VIRTIOFSD_LOG}"

# Trap to clean up on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -P $$ virtiofsd 2>/dev/null || true
    rm -f "${TRACEE_SOCK}"
    echo "Done."
}
trap cleanup EXIT INT TERM

echo "Configuration:"
echo "  VM Name:        ${VM_NAME}"
echo "  VM Image:       ${VM_DISK}"
echo "  Target arch:    ${TARGET_ARCH}"
echo "  RAM:            ${VM_RAM}"
echo "  CPUs:           ${VM_CPUS}"
echo "  SSH Port:       localhost:${SSH_PORT}"
echo "  Tracee Dir:     ${TRACEE_DIR}"
echo "  Disk format:    ${VM_FORMAT}"
echo "  Host UID:GID:   $(id -u):$(id -g)"
echo "  VM UID:GID:     1000:1000 (mapped to host)"
echo ""

# Start virtiofsd only when using KVM (native arch)
VIRTIOFSD_PID=""
if [[ "${USE_VIRTIOFS}" -eq 1 ]]; then
    if ! command -v "${VIRTIOFSD}" &> /dev/null; then
        echo -e "${RED}Error: virtiofsd not found at ${VIRTIOFSD}${NC}"
        echo "Try: which virtiofsd || find /usr -name virtiofsd 2>/dev/null"
        echo ""
        echo "Install with:"
        echo "  Fedora: sudo dnf install qemu-virtiofsd"
        echo "  Ubuntu: sudo apt install qemu-system-gui"
        exit 1
    fi
    echo "Starting virtiofsd for tracee..."
    echo "  Log file: ${VIRTIOFSD_LOG}"
    "${VIRTIOFSD}" \
        --socket-path="${TRACEE_SOCK}" \
        --shared-dir="${TRACEE_DIR}" \
        --cache=never \
        --sandbox=none \
        --inode-file-handles=never \
        --translate-uid="map:1000:$(id -u):1" \
        --translate-gid="map:1000:$(id -g):1" \
        >> "${VIRTIOFSD_LOG}" 2>&1 &
    VIRTIOFSD_PID=$!

    echo "Waiting for virtiofsd socket..."
    for i in {1..15}; do
        if [ -S "${TRACEE_SOCK}" ]; then
            if ! kill -0 "${VIRTIOFSD_PID}" 2>/dev/null; then
                echo -e "${RED}Error: virtiofsd process died${NC}"
                echo "Check log: ${VIRTIOFSD_LOG}"
                tail -20 "${VIRTIOFSD_LOG}"
                exit 1
            fi
            echo -e "${GREEN}✓ Socket ready! (PID: ${VIRTIOFSD_PID})${NC}"
            break
        fi
        if [ $i -eq 15 ]; then
            echo -e "${RED}Error: Timeout waiting for socket${NC}"
            echo "Check log: ${VIRTIOFSD_LOG}"
            tail -20 "${VIRTIOFSD_LOG}"
            exit 1
        fi
        sleep 1
    done
    ls -lh "${TRACEE_SOCK}"
    echo ""
else
    echo -e "${YELLOW}Virtiofs disabled (cross-arch TCG). Using 9p for shared directories.${NC}"
    echo "  Shared: ${TRACEE_DIR} → /mnt/tracee (via 9p)"
    echo ""
fi

# Build QEMU command based on target architecture
QEMU_CMD=()
if [[ "${TARGET_ARCH}" == "aarch64" ]]; then
    QEMU_BINARY="qemu-system-aarch64"
    if ! command -v "${QEMU_BINARY}" &>/dev/null; then
        echo -e "${RED}Error: ${QEMU_BINARY} not found. Install qemu-system-aarch64.${NC}"
        exit 1
    fi
    # Find UEFI firmware code and vars template
    AARCH64_CODE=""
    AARCH64_VARS_TEMPLATE=""
    for fw in /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/edk2/aarch64/QEMU_EFI.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
        [[ -f "${fw}" ]] && { AARCH64_CODE="${fw}"; break; }
    done
    for vars in /usr/share/AAVMF/AAVMF_VARS.fd /usr/share/edk2/aarch64/QEMU_VARS.fd; do
        [[ -f "${vars}" ]] && { AARCH64_VARS_TEMPLATE="${vars}"; break; }
    done
    if [[ -z "${AARCH64_CODE}" ]] || [[ -z "${AARCH64_VARS_TEMPLATE}" ]]; then
        echo -e "${RED}Error: aarch64 UEFI firmware not found.${NC}"
        echo "Install one of: edk2-aarch64, qemu-efi-aarch64, AAVMF"
        exit 1
    fi
    # Per-VM writable copy of EFI variable store
    AARCH64_VARS="${VM_DIR}/${VM_NAME}-efivars.fd"
    if [[ ! -f "${AARCH64_VARS}" ]]; then
        cp "${AARCH64_VARS_TEMPLATE}" "${AARCH64_VARS}"
        echo "  Created EFI vars: $(basename "${AARCH64_VARS}")"
    fi
    echo "  UEFI code:      ${AARCH64_CODE}"
    echo "  UEFI vars:      ${AARCH64_VARS}"

    QEMU_CMD=("${QEMU_BINARY}" -machine "virt,gic-version=max")
    if [[ "${USE_KVM}" -eq 1 ]]; then
        QEMU_CMD+=(-enable-kvm -cpu host -m "${VM_RAM}" -smp "${VM_CPUS}")
    else
        # TCG cross-arch
        QEMU_CMD+=(-cpu cortex-a57 -m "${VM_RAM}" -smp "${VM_CPUS}")
        echo -e "${YELLOW}  Cross-arch emulation (TCG) — ${VM_CPUS} cores, ${VM_RAM} RAM, will be slow.${NC}"
    fi
    QEMU_CMD+=(
        # UEFI firmware (pflash): read-only code + writable per-VM variable store
        -drive "if=pflash,format=raw,file=${AARCH64_CODE},readonly=on"
        -drive "if=pflash,format=raw,file=${AARCH64_VARS}"
    )
    # Virtiofs (KVM only) or 9p fallback for cross-arch TCG
    if [[ "${USE_VIRTIOFS}" -eq 1 ]]; then
        QEMU_CMD+=(
            -object "memory-backend-memfd,id=mem,size=${VM_RAM},share=on"
            -numa node,memdev=mem
            -chardev "socket,id=char-tracee,path=${TRACEE_SOCK}"
            -device vhost-user-fs-pci,chardev=char-tracee,tag=tracee
        )
    else
        # 9p filesystem sharing: works with TCG (no shared memory needed)
        QEMU_CMD+=(
            -fsdev "local,id=tracee_dev,path=${TRACEE_DIR},security_model=none"
            -device "virtio-9p-pci,fsdev=tracee_dev,mount_tag=tracee"
        )
    fi
    QEMU_CMD+=(
        -drive "if=virtio,format=${VM_FORMAT},file=${VM_DISK}"
    )
    if [ -f "${VM_DIR}/${VM_NAME}-cloud-init.iso" ]; then
        QEMU_CMD+=(-drive "if=virtio,format=raw,file=${VM_DIR}/${VM_NAME}-cloud-init.iso,readonly=on")
    fi
    QEMU_CMD+=(
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
        -device virtio-net-pci,netdev=net0
        -nographic
    )
else
    # x86_64: SeaBIOS (QEMU default) works for all Ubuntu cloud images (hybrid GPT).
    QEMU_CMD=(
        qemu-system-x86_64
        -enable-kvm
        -cpu host
        -m "${VM_RAM}"
        -smp "${VM_CPUS}"
        # Shared memory for virtiofs
        -object "memory-backend-memfd,id=mem,size=${VM_RAM},share=on"
        -numa node,memdev=mem
        # Virtiofs for tracee
        -chardev "socket,id=char-tracee,path=${TRACEE_SOCK}"
        -device vhost-user-fs-pci,chardev=char-tracee,tag=tracee
        # Main disk
        -drive "if=virtio,format=${VM_FORMAT},file=${VM_DISK}"
    )
    if [ -f "${VM_DIR}/${VM_NAME}-cloud-init.iso" ]; then
        QEMU_CMD+=(-cdrom "${VM_DIR}/${VM_NAME}-cloud-init.iso")
    fi
    QEMU_CMD+=(
        -net nic,model=virtio
        -net "user,hostfwd=tcp::${SSH_PORT}-:22"
        -nographic
        -serial mon:stdio
    )
fi

echo ""
echo "Starting QEMU..."
echo ""
echo -e "${GREEN}VM is starting...${NC}"
echo "SSH access: ssh -p ${SSH_PORT} ubuntu@localhost"
if [[ -n "${VIRTIOFSD_PID}" ]]; then
    echo ""
    echo "Debug info:"
    echo "  virtiofsd PID: ${VIRTIOFSD_PID}"
    echo "  virtiofsd log: ${VIRTIOFSD_LOG}"
fi
echo ""
echo "Press Ctrl+A then X to quit QEMU"
echo "════════════════════════════════════════════════════════════"
echo ""

# Start QEMU (foreground)
exec "${QEMU_CMD[@]}"
