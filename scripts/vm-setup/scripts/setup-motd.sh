#!/bin/sh
# Setup dynamic MOTD for Tracee Development VM
# Shows running vs expected kernel, highlights mismatch on login.
#
# Usage: setup-motd.sh <distro> <version> <kernel_flavor> <kernel_version> [ssh_key_name]
#
# NOTE: Currently embedded for reliability, but may be fetched from
#       the repo branch in the future (like other scripts).

DISTRO="${1:?Usage: setup-motd.sh <distro> <version> <flavor> <kernel_version> [ssh_key_name]}"
VERSION="${2:?}"
KERNEL_FLAVOR="${3:?}"
KERNEL_VERSION="${4:?}"
SSH_KEY_NAME="${5:-none}"

# Clear default static MOTD
: > /etc/motd

# Disable default MOTD scripts (Ubuntu ads, help text, etc.)
# No-op on distros without update-motd.d
if [ -d /etc/update-motd.d ]; then
    chmod -x /etc/update-motd.d/* 2>/dev/null || true
fi

# Write our dynamic MOTD script
cat > /etc/update-motd.d/01-tracee << 'MOTD_EOF'
#!/bin/sh
EXPECTED_FLAVOR="__KERNEL_FLAVOR__"
EXPECTED_VERSION="__KERNEL_VERSION__"
RUNNING_KERNEL=$(uname -r)

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "            Welcome to Tracee Development VM"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Distro:     __DISTRO__ __VERSION__"

# Check if running kernel matches expected
case "$RUNNING_KERNEL" in
  *"$EXPECTED_VERSION"*)
    echo "  Kernel:     $EXPECTED_FLAVOR $EXPECTED_VERSION (running: $RUNNING_KERNEL) ✓"
    ;;
  *)
    echo "  Kernel:     $EXPECTED_FLAVOR $EXPECTED_VERSION (expected)"
    echo "  Running:    $RUNNING_KERNEL  ← MISMATCH (reboot may be needed)"
    ;;
esac

if [ "__SSH_KEY_NAME__" != "none" ]; then
  echo "  SSH Key:    ~/.ssh/__SSH_KEY_NAME__"
fi
echo "  Console:    ubuntu / ubuntu (for emergency access)"
echo "  Project:    https://github.com/aquasecurity/tracee"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
MOTD_EOF

# Replace placeholders with actual values
sed -i "s|__DISTRO__|${DISTRO}|g" /etc/update-motd.d/01-tracee
sed -i "s|__VERSION__|${VERSION}|g" /etc/update-motd.d/01-tracee
sed -i "s|__KERNEL_FLAVOR__|${KERNEL_FLAVOR}|g" /etc/update-motd.d/01-tracee
sed -i "s|__KERNEL_VERSION__|${KERNEL_VERSION}|g" /etc/update-motd.d/01-tracee
sed -i "s|__SSH_KEY_NAME__|${SSH_KEY_NAME}|g" /etc/update-motd.d/01-tracee

chmod +x /etc/update-motd.d/01-tracee

echo "Dynamic MOTD installed"
