#!/bin/bash
# Script to debug VM images - check logs, user configuration, and cloud-init status
# Usage: ./debug-vm.sh -i <qcow2-file> [-l log-file-path]

set -e

usage() {
    cat << EOF
Usage: $0 -i <qcow2-file> [-l log-file-path] [-m method]

Options:
    -i, --image     Path to qcow2 image file (required)
    -l, --log       Log file path to display (default: /var/log/tracee-vm-init.log)
    -m, --method    Mount method: guestmount, guestfish, or nbd (default: guestfish)
                    - guestfish: Use libguestfs (works with locked images, requires libguestfs-tools)
                    - guestmount: Use FUSE mount (requires libguestfs-tools)
                    - nbd: Use qemu-nbd (requires VM to be stopped)
    -h, --help      Show this help message

Examples:
    $0 -i ~/vms/ubuntu-22.04-generic-5.19.0-50-x86_64.qcow2
    $0 -i ~/vms/my-vm.qcow2 -l /var/log/cloud-init.log
    $0 -i ~/vms/my-vm.qcow2 -m nbd
EOF
    exit 1
}

QCOW2_FILE=""
LOG_FILE="/var/log/tracee-vm-init.log"
METHOD="guestfish"

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            QCOW2_FILE="$2"
            shift 2
            ;;
        -l|--log)
            LOG_FILE="$2"
            shift 2
            ;;
        -m|--method)
            METHOD="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [ -z "$QCOW2_FILE" ]; then
    echo "Error: Image file is required"
    usage
fi

# Expand tilde in path
QCOW2_FILE="${QCOW2_FILE/#\~/$HOME}"

MOUNT_POINT="/mnt/vm-debug-$$"
NBD_DEVICE="/dev/nbd0"

if [ ! -f "$QCOW2_FILE" ]; then
    echo "Error: qcow2 file not found: $QCOW2_FILE"
    exit 1
fi

# Check if the image is valid and show info
echo "=== Image information ==="
echo "File: $QCOW2_FILE"
echo "Size: $(du -h "$QCOW2_FILE" | cut -f1)"
echo ""

# Check if processes are using the file
echo "=== Checking for processes using this image ==="
PROCS=$(sudo fuser "$QCOW2_FILE" 2>/dev/null || true)
if [ -n "$PROCS" ]; then
    echo "⚠️  WARNING: Image is currently in use by process(es): $PROCS"
    echo ""
    echo "Processes:"
    for pid in $PROCS; do
        ps -p "$pid" -o pid,cmd 2>/dev/null || true
    done
    echo ""
    if [ "$METHOD" != "guestfish" ]; then
        echo "ERROR: Cannot mount with '$METHOD' while VM is running."
        echo "Options:"
        echo "  1. Stop the VM and try again"
        echo "  2. Use guestfish method: -m guestfish"
        exit 1
    fi
    echo "Continuing with guestfish (can read locked images)..."
else
    echo "No processes currently using the image."
fi
echo ""

# Method-specific functions
use_guestfish() {
    if ! command -v guestfish &> /dev/null; then
        echo "Error: guestfish not found. Install with: sudo dnf install libguestfs-tools"
        exit 1
    fi
    
    echo "Using guestfish to access $QCOW2_FILE..."
    echo ""
    
    # First check if we can access the filesystem at all
    echo "=== Filesystem inspection ==="
    if ! sudo guestfish --ro -a "$QCOW2_FILE" -i ls / &>/dev/null; then
        echo "ERROR: Cannot access filesystem. Trying without auto-mount..."
        echo ""
        echo "=== Available filesystems ==="
        sudo guestfish --ro -a "$QCOW2_FILE" <<EOF
run
list-filesystems
EOF
        echo ""
        echo "This suggests the image may be corrupted or cloud-init hasn't created the filesystem yet."
        return 1
    fi
    
    echo "Root directory contents:"
    sudo guestfish --ro -a "$QCOW2_FILE" -i ls / | head -20
    echo ""
    
    # Check if /var/log exists
    if ! sudo guestfish --ro -a "$QCOW2_FILE" -i ls /var/log/ &>/dev/null; then
        echo "ERROR: /var/log directory doesn't exist!"
        echo "This suggests cloud-init has not run yet or the system hasn't booted."
        echo ""
        echo "Checking /var directory:"
        sudo guestfish --ro -a "$QCOW2_FILE" -i ls /var/ 2>/dev/null || echo "Cannot list /var"
        return 1
    fi
    
    # Try to cat the log file
    echo "=== Contents of $LOG_FILE ==="
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat "$LOG_FILE" 2>/dev/null; then
        echo ""
        echo "=== End of log file ==="
    else
        echo "Log file not found: $LOG_FILE"
    fi
    
    echo ""
    echo "=== All files in /var/log ==="
    sudo guestfish --ro -a "$QCOW2_FILE" -i ll /var/log/ 2>/dev/null | head -30
    
    echo ""
    echo "=== Cloud-init related files ==="
    sudo guestfish --ro -a "$QCOW2_FILE" -i ll /var/log/ 2>/dev/null | grep -i cloud || echo "No cloud-init logs found"
    
    echo ""
    echo "=== Checking cloud-init status ==="
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat /var/lib/cloud/instance/boot-finished 2>/dev/null; then
        echo "Cloud-init boot finished marker found"
    else
        echo "Cloud-init boot NOT finished - the system may still be initializing or cloud-init failed"
    fi
    
    echo ""
    echo "=== Most recent cloud-init log (if exists) ==="
    sudo guestfish --ro -a "$QCOW2_FILE" -i cat /var/log/cloud-init-output.log 2>/dev/null | tail -100 || echo "No cloud-init-output.log found"
    
    echo ""
    echo "=== User Configuration Check ==="
    
    echo "Checking if users exist:"
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat /etc/passwd 2>/dev/null | grep -E "^(ubuntu|ec2-user|alpine):" ; then
        echo "✓ User found"
    else
        echo "✗ User NOT found - cloud-init users module likely failed"
    fi
    echo ""
    
    echo "Checking password configuration:"
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat /etc/shadow 2>/dev/null | grep -E "^(ubuntu|ec2-user|alpine):" ; then
        echo "✓ Password hash exists"
    else
        echo "✗ No password hash - password login will fail"
    fi
    echo ""
    
    echo "Checking SSH authorized_keys:"
    for user_home in /home/ubuntu /home/ec2-user /home/alpine /root; do
        if sudo guestfish --ro -a "$QCOW2_FILE" -i cat "${user_home}/.ssh/authorized_keys" 2>/dev/null; then
            echo "✓ Found authorized_keys in ${user_home}"
            break
        fi
    done 2>&1 | grep -q "✓" || echo "✗ No authorized_keys file found - SSH key login will fail"
    echo ""
    
    echo "Checking SSH server configuration:"
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat /etc/ssh/sshd_config 2>/dev/null | grep -E "^(PasswordAuthentication|PubkeyAuthentication|PermitRootLogin)" ; then
        echo "✓ SSH config found"
    else
        echo "⚠ Could not read SSH config"
    fi
    echo ""
    
    echo "Checking user groups:"
    if sudo guestfish --ro -a "$QCOW2_FILE" -i cat /etc/group 2>/dev/null | grep -E "^(docker|sudo|wheel):" ; then
        echo "✓ Groups configured"
    else
        echo "⚠ Standard groups not found"
    fi
    
    echo ""
    echo "=== Cloud-init errors (last 50 lines) ==="
    sudo guestfish --ro -a "$QCOW2_FILE" -i cat /var/log/cloud-init.log 2>/dev/null | grep -A 5 -i "error\|fail\|exception\|traceback" | tail -50 || echo "No errors found"
    
    echo ""
    echo "=== To explore interactively, run: ==="
    echo "sudo guestfish --ro -a '$QCOW2_FILE' -i"
}

use_guestmount() {
    if ! command -v guestmount &> /dev/null; then
        echo "Error: guestmount not found. Install with: sudo dnf install libguestfs-tools"
        exit 1
    fi
    
    echo "Using guestmount to access $QCOW2_FILE..."
    sudo mkdir -p "$MOUNT_POINT"
    
    echo "Mounting image at $MOUNT_POINT..."
    sudo guestmount -a "$QCOW2_FILE" -i --ro "$MOUNT_POINT"
    
    display_logs_and_wait
}

use_nbd() {
    echo "Using qemu-nbd to access $QCOW2_FILE..."
    
    # Load NBD module
    if ! lsmod | grep -q nbd; then
        echo "Loading NBD kernel module..."
        sudo modprobe nbd max_part=8
    fi
    
    # Connect qcow2 to NBD device (read-only)
    echo "Connecting image to $NBD_DEVICE (read-only)..."
    sudo qemu-nbd --read-only --connect="$NBD_DEVICE" "$QCOW2_FILE"
    
    # Wait for partitions to be detected
    sleep 2
    
    # Show partition information
    echo "Partitions found:"
    sudo fdisk -l "$NBD_DEVICE" | grep "^$NBD_DEVICE"
    
    # Determine the root partition (usually p1 or p2)
    if [ -b "${NBD_DEVICE}p1" ]; then
        ROOT_PART="${NBD_DEVICE}p1"
    elif [ -b "${NBD_DEVICE}p2" ]; then
        ROOT_PART="${NBD_DEVICE}p2"
    else
        echo "Error: Could not find root partition"
        exit 1
    fi
    
    echo "Using root partition: $ROOT_PART"
    
    # Create mount point and mount (read-only)
    sudo mkdir -p "$MOUNT_POINT"
    sudo mount -o ro "$ROOT_PART" "$MOUNT_POINT"
    
    display_logs_and_wait
}

display_logs_and_wait() {
    echo ""
    echo "=== Image mounted at $MOUNT_POINT ==="
    echo ""
    
    # Try to display the requested log file
    FULL_LOG_PATH="${MOUNT_POINT}${LOG_FILE}"
    if [ -f "$FULL_LOG_PATH" ]; then
        echo "=== Contents of $LOG_FILE ==="
        sudo cat "$FULL_LOG_PATH"
        echo ""
        echo "=== End of log file ==="
    else
        echo "Log file not found: $LOG_FILE"
        echo ""
        echo "Available log files in /var/log:"
        sudo ls -lh "${MOUNT_POINT}/var/log/" 2>/dev/null || echo "Could not list /var/log"
    fi
    
    echo ""
    echo "=== Other useful logs to check ==="
    echo "Cloud-init logs:"
    sudo ls -lh "${MOUNT_POINT}/var/log/cloud-init"* 2>/dev/null || echo "No cloud-init logs found"
    
    echo ""
    echo "Press Enter to unmount and exit, or Ctrl+C to keep mounted for manual inspection..."
    read
}

cleanup() {
    echo "Cleaning up..."
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        sudo umount "$MOUNT_POINT" 2>/dev/null || sudo fusermount -u "$MOUNT_POINT" 2>/dev/null || true
    fi
    if [ -d "$MOUNT_POINT" ]; then
        sudo rmdir "$MOUNT_POINT" 2>/dev/null || true
    fi
    if [ -b "$NBD_DEVICE" ]; then
        sudo qemu-nbd --disconnect "$NBD_DEVICE" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Execute the appropriate method
case "$METHOD" in
    guestfish)
        use_guestfish
        ;;
    guestmount)
        use_guestmount
        ;;
    nbd)
        use_nbd
        ;;
    *)
        echo "Error: Invalid method '$METHOD'. Must be: guestfish, guestmount, or nbd"
        usage
        ;;
esac
