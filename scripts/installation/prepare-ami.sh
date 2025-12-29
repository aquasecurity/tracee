#!/bin/bash

# Prepare AMI for Tracee CI/CD
# This script prepares an AMI with all required dependencies for running Tracee tests.
# Supports Ubuntu and CentOS/RHEL-based distributions.
#
# Usage: prepare-ami.sh [--force] [--skip-images] [--skip-deps]
#   --force          Clean docker state and caches before setup
#   --skip-images    Skip pulling test container images
#   --skip-deps      Skip installing dependencies (only disable auto-updates)

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Options
FORCE="false"
SKIP_IMAGES="false"
SKIP_DEPS="false"

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force | -f)
                FORCE="true"
                shift
                ;;
            --skip-images)
                SKIP_IMAGES="true"
                shift
                ;;
            --skip-deps)
                SKIP_DEPS="true"
                shift
                ;;
            --help | -h)
                echo "Usage: ${0##*/} [--force] [--skip-images] [--skip-deps]"
                echo "  --force, -f      Clean docker state and caches before setup"
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

# Update system packages
update_system() {
    local distro="$1"

    case "${distro}" in
        ubuntu)
            info "Updating system packages (Ubuntu)"
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || die "apt-get update failed"
            apt-get upgrade -y || die "apt-get upgrade failed"
            info "System packages updated successfully"
            ;;
        centos)
            info "Updating system packages (CentOS/RHEL)"
            if command -v dnf > /dev/null 2>&1; then
                dnf upgrade -y || die "dnf upgrade failed"
            elif command -v yum > /dev/null 2>&1; then
                yum upgrade -y || die "yum upgrade failed"
            fi
            info "System packages updated successfully"
            ;;
        alpine)
            info "Updating system packages (Alpine)"
            apk update || die "apk update failed"
            apk upgrade || die "apk upgrade failed"
            info "System packages updated successfully"
            ;;
        *)
            warn "Unknown distro for system update: ${distro}"
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

# Clean docker state (for --force)
clean_docker_state() {
    info "Cleaning Docker state (prune all unused images, containers, networks)..."

    if ! command -v docker > /dev/null 2>&1; then
        warn "Docker not installed, skipping docker cleanup"
        return 0
    fi

    # Prune all unused images, containers, networks, and build cache
    docker system prune -a -f || warn "docker system prune failed"

    info "Docker state cleaned"
}

# Install AMI-specific tooling (AWS CLI, GitHub CLI, Actions Runner)
install_ami_tooling() {
    info "Installing AMI tooling (AWS CLI, GitHub CLI, Actions Runner)"

    if [[ -x "${SCRIPT_DIR}/install-ami-tooling.sh" ]]; then
        sh "${SCRIPT_DIR}/install-ami-tooling.sh"
    else
        die "install-ami-tooling.sh not found or not executable"
    fi
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

# Clean package manager caches (Ubuntu/Debian)
clean_apt_cache() {
    info "Cleaning APT caches..."

    apt-get clean || warn "apt-get clean failed"
    apt-get autoclean || warn "apt-get autoclean failed"
    apt-get autoremove -y || warn "apt-get autoremove failed"
    rm -rf /var/lib/apt/lists/*

    info "APT caches cleaned"
}

# Clean package manager caches (CentOS/RHEL)
clean_yum_cache() {
    info "Cleaning YUM/DNF caches..."

    if command -v dnf > /dev/null 2>&1; then
        dnf clean all || warn "dnf clean all failed"
    elif command -v yum > /dev/null 2>&1; then
        yum clean all || warn "yum clean all failed"
    fi

    rm -rf /var/cache/dnf/* /var/cache/yum/*

    info "YUM/DNF caches cleaned"
}

# Clean log files (all distros)
clean_logs() {
    info "Cleaning log files..."

    rm -rf /var/log/*.log 2> /dev/null || true
    rm -rf /var/log/*/*.log 2> /dev/null || true

    info "Log files cleaned"
}

# Final cleanup based on distro
final_cleanup() {
    local distro="$1"

    info "Performing final cleanup..."

    # Clean logs for all distros
    clean_logs

    # Distro-specific cleanup
    case "${distro}" in
        ubuntu)
            clean_apt_cache
            ;;
        centos)
            clean_yum_cache
            ;;
        alpine)
            info "Cleaning APK cache..."
            rm -rf /var/cache/apk/* 2> /dev/null || true
            ;;
    esac

    info "Final cleanup completed"
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

    # Step 0 (optional): Clean docker state if --force
    if [[ "${FORCE}" == "true" ]]; then
        info "Step 0/7: Cleaning Docker state (--force)..."
        clean_docker_state
    fi

    # Step 1: Disable automatic updates (before any package operations)
    info "Step 1/7: Disabling automatic updates..."
    disable_auto_updates "${distro}"

    # Step 2: Update system packages
    info "Step 2/7: Updating system packages..."
    update_system "${distro}"

    # Step 3: Install dependencies
    if [[ "${SKIP_DEPS}" == "false" ]]; then
        info "Step 3/7: Installing dependencies..."
        install_deps "${distro}"
    else
        info "Step 3/7: Skipping dependency installation (--skip-deps)"
    fi

    # Step 4: Install AMI-specific tooling (AWS CLI, GitHub CLI, Actions Runner)
    info "Step 4/7: Installing AMI tooling..."
    install_ami_tooling

    # Step 5: Pull test images
    if [[ "${SKIP_IMAGES}" == "false" ]]; then
        info "Step 5/7: Pulling test container images..."
        pull_test_images
    else
        info "Step 5/7: Skipping image pull (--skip-images)"
    fi

    # Step 6: Final safeguard - ensure auto-updates remain disabled
    info "Step 6/7: Final safeguard - ensuring auto-updates remain disabled..."
    disable_auto_updates "${distro}"

    # Step 7: Final cleanup (logs, package caches)
    info "Step 7/7: Final cleanup..."
    final_cleanup "${distro}"

    info "=== AMI Preparation Completed Successfully ==="
    info "The AMI is now ready for Tracee CI/CD operations."
}

main "$@"
