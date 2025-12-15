#!/bin/bash

# Prepare AMI for Tracee CI/CD
# This script prepares an AMI with all required dependencies for running Tracee tests.
# Supports Ubuntu and CentOS/RHEL-based distributions.
#
# Usage: prepare-ami.sh [--skip-images] [--skip-deps]
#   --skip-images    Skip pulling test container images
#   --skip-deps      Skip installing dependencies (only disable auto-updates)

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Options
SKIP_IMAGES="false"
SKIP_DEPS="false"

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-images)
                SKIP_IMAGES="true"
                shift
                ;;
            --skip-deps)
                SKIP_DEPS="true"
                shift
                ;;
            --help | -h)
                echo "Usage: ${0##*/} [--skip-images] [--skip-deps]"
                echo "  --skip-images    Skip pulling test container images"
                echo "  --skip-deps      Skip installing dependencies"
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

# Detect the Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case "${ID}" in
            ubuntu | debian)
                echo "ubuntu"
                ;;
            centos | rhel | fedora | rocky | almalinux | amzn)
                echo "centos"
                ;;
            alpine)
                echo "alpine"
                ;;
            *)
                # Check for RHEL-like by ID_LIKE
                if [[ "${ID_LIKE:-}" == *"rhel"* ]] || [[ "${ID_LIKE:-}" == *"centos"* ]] || [[ "${ID_LIKE:-}" == *"fedora"* ]]; then
                    echo "centos"
                elif [[ "${ID_LIKE:-}" == *"debian"* ]]; then
                    echo "ubuntu"
                else
                    die "Unsupported distribution: ${ID}"
                fi
                ;;
        esac
    else
        die "Cannot detect distribution: /etc/os-release not found"
    fi
}

# Check if running in a container (no systemd)
is_container() {
    # Check for container indicators
    if [[ -f /.dockerenv ]]; then
        return 0
    fi
    if grep -q 'docker\|lxc\|containerd' /proc/1/cgroup 2> /dev/null; then
        return 0
    fi
    if [[ "$(cat /proc/1/comm 2> /dev/null)" != "systemd" ]]; then
        return 0
    fi
    return 1
}

# Disable automatic updates for Ubuntu
disable_auto_updates_ubuntu() {
    info "Disabling unattended upgrades (Ubuntu)"

    if is_container; then
        info "Running in container - skipping systemd-based unattended-upgrades disable"
        # In containers, just try to remove the package if apt is available
        if command -v apt-get > /dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get -y purge unattended-upgrades 2> /dev/null || true
        fi
        return 0
    fi

    if [[ -x "${__LIB_DIR}/disable-unattended-upgrades.sh" ]]; then
        "${__LIB_DIR}/disable-unattended-upgrades.sh"
    else
        warn "disable-unattended-upgrades.sh not found or not executable"
    fi
}

# Disable automatic updates for CentOS/RHEL
disable_auto_updates_centos() {
    info "Disabling automatic updates (CentOS/RHEL)"

    if is_container; then
        info "Running in container - skipping systemd-based auto-update disable"
        # In containers, just try to remove the packages if available
        if command -v dnf > /dev/null 2>&1; then
            dnf remove -y dnf-automatic 2> /dev/null || true
        elif command -v yum > /dev/null 2>&1; then
            yum remove -y yum-cron 2> /dev/null || true
        fi
        return 0
    fi

    require_cmds systemctl

    # Disable dnf-automatic if installed
    local units=(
        "dnf-automatic.timer"
        "dnf-automatic-install.timer"
        "dnf-automatic-notifyonly.timer"
        "dnf-automatic-download.timer"
        "yum-cron.service"
        "packagekit.service"
    )

    for unit in "${units[@]}"; do
        if systemctl list-unit-files | grep -q "^${unit}"; then
            info "Disabling ${unit}"
            systemctl stop "${unit}" 2> /dev/null || true
            systemctl disable "${unit}" 2> /dev/null || true
            systemctl mask "${unit}" 2> /dev/null || true
        fi
    done

    # Remove dnf-automatic and yum-cron if installed
    if command -v dnf > /dev/null 2>&1; then
        dnf remove -y dnf-automatic 2> /dev/null || true
    elif command -v yum > /dev/null 2>&1; then
        yum remove -y yum-cron 2> /dev/null || true
    fi

    systemctl daemon-reload

    info "Automatic updates disabled successfully"
}

# Disable automatic updates based on distro
disable_auto_updates() {
    local distro="$1"

    case "${distro}" in
        ubuntu)
            disable_auto_updates_ubuntu
            ;;
        centos)
            disable_auto_updates_centos
            ;;
        alpine)
            info "Alpine Linux does not have automatic updates by default"
            ;;
        *)
            warn "Unknown distro for auto-update disable: ${distro}"
            ;;
    esac
}

# Install dependencies based on distro
install_deps() {
    local distro="$1"

    case "${distro}" in
        ubuntu)
            info "Installing dependencies for Ubuntu"
            bash "${SCRIPT_DIR}/install-deps-ubuntu.sh"
            ;;
        centos)
            info "Installing dependencies for CentOS/RHEL"
            bash "${SCRIPT_DIR}/install-deps-centos.sh"
            ;;
        alpine)
            info "Installing dependencies for Alpine"
            sh "${SCRIPT_DIR}/install-deps-alpine.sh"
            ;;
        *)
            die "No installation script for distro: ${distro}"
            ;;
    esac
}

# Pull test container images
pull_test_images() {
    info "Pulling test container images"

    if [[ -x "${SCRIPT_DIR}/pull-test-images.sh" ]]; then
        bash "${SCRIPT_DIR}/pull-test-images.sh"
    else
        warn "pull-test-images.sh not found or not executable"
    fi
}

# Main function
main() {
    parse_args "$@"

    info "=== Tracee AMI Preparation ==="
    info "Starting AMI preparation..."

    # Detect distribution
    local distro
    distro=$(detect_distro)
    info "Detected distribution: ${distro}"

    # Step 1: Disable automatic updates (before any package operations)
    info "Step 1/4: Disabling automatic updates..."
    disable_auto_updates "${distro}"

    # Step 2: Install dependencies
    if [[ "${SKIP_DEPS}" == "false" ]]; then
        info "Step 2/4: Installing dependencies..."
        install_deps "${distro}"
    else
        info "Step 2/4: Skipping dependency installation (--skip-deps)"
    fi

    # Step 3: Pull test images
    if [[ "${SKIP_IMAGES}" == "false" ]]; then
        info "Step 3/4: Pulling test container images..."
        pull_test_images
    else
        info "Step 3/4: Skipping image pull (--skip-images)"
    fi

    # Step 4: Final safeguard - ensure auto-updates remain disabled
    info "Step 4/4: Final safeguard - ensuring auto-updates remain disabled..."
    disable_auto_updates "${distro}"

    info "=== AMI Preparation Completed Successfully ==="
    info "The AMI is now ready for Tracee CI/CD operations."
}

main "$@"
