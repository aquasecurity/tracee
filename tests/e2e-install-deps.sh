#!/bin/bash

set -e
set -x # for debugging

# Source lib.sh for consistent logging and utilities
__LIB_DIR="${0%/*}/../scripts"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - must match centralized install script
CLANG_VERSION=19

# Path to centralized Clang installation script
INSTALL_SCRIPT="${0%/*}/../scripts/installation/install-clang.sh"

# This script installs the dependencies for compiling tracee and running the e2e
# tests. Note that for llvm, binaries might be installed from the OS package
# manager or from github, depending on the OS version. This happens because
# upstream llvm binaries are not available for all OS versions.
#
# Note that a full "apt-get dist-upgrade" is performed. This makes the entire
# test suite run slower, but it is necessary to ensure that the OS is up to
# date when installing the compiler toolchain.
#
# If AMIs need to be updated, you can provision an AMI and run this script on
# it. It will install dependencies and update the OS. You may then create a new
# AMI from the provisioned one (and stop using this script until new changes
# are required).

ARCH=$(uname -m)

wait_for_apt_locks() {
    local lock="/var/lib/dpkg/lock"
    local lock_frontend="/var/lib/dpkg/lock-frontend"
    local lock_lists="/var/lib/apt/lists/lock"
    local lock_archives="/var/cache/apt/archives/lock"

    local timeout=20
    local elapsed=0
    local wait_interval=2

    echo "Checking for unattended-upgrades..."
    while pgrep -f unattended-upgrades > /dev/null; do
        if ( (elapsed > = timeout)); then
            echo "Timed out waiting for unattended-upgrades to finish. Attempting to kill..."
            pkill -SIGQUIT -f unattended-upgrades || true
            pkill -SIGKILL -f unattended-upgrades || true
            break
        fi

        echo "unattended-upgrades is still running. Waiting..."
        sleep $wait_interval
        ( (elapsed += wait_interval))
    done

    timeout=5 # reduce timeout for apt locks
    elapsed=0 # reset timer

    while :; do
        if ! fuser $lock > /dev/null 2>&1 \
            && ! fuser $lock_frontend > /dev/null 2>&1 \
            && ! fuser $lock_lists > /dev/null 2>&1 \
            && ! fuser $lock_archives > /dev/null 2>&1; then
            echo "All apt locks are free."
            break
        fi

        if ( (elapsed > = timeout)); then
            echo "Timed out waiting for apt locks to be released. Attempting to kill locking processes."
            fuser -k -SIGQUIT $lock > /dev/null 2>&1 || true
            fuser -k -SIGQUIT $lock_frontend > /dev/null 2>&1 || true
            fuser -k -SIGQUIT $lock_lists > /dev/null 2>&1 || true
            fuser -k -SIGQUIT $lock_archives > /dev/null 2>&1 || true

            # Give some time for processes to terminate gracefully
            sleep 2

            fuser -k -SIGKILL $lock > /dev/null 2>&1 || true
            fuser -k -SIGKILL $lock_frontend > /dev/null 2>&1 || true
            fuser -k -SIGKILL $lock_lists > /dev/null 2>&1 || true
            fuser -k -SIGKILL $lock_archives > /dev/null 2>&1 || true

            # Delete lock files if they still exist
            rm -f $lock $lock_frontend $lock_lists $lock_archives

            echo "Forced removal of processes locking apt. System may be in an inconsistent state."
            break
        fi

        echo "Waiting for other software managers to finish..."
        sleep $wait_interval
        ( (elapsed += wait_interval))
    done
}

disable_unattended_upgrades() {
    # This is a pain point. Make sure to always disable anything touching the
    # dpkg database, otherwise it will fail with locking errors.
    systemctl stop unattended-upgrades || true
    systemctl disable --now unattended-upgrades || true

    wait_for_apt_locks
    apt-get remove -y --purge unattended-upgrades || true
    apt-get remove -y --purge ubuntu-advantage-tools || true
}

remove_golang_alternatives() {
    update-alternatives --remove-all go || true
    update-alternatives --remove-all gofmt || true
}

remove_golang_usr_bin_files() {
    rm -f /usr/bin/go
    rm -f /usr/bin/gofmt
}

link_golang_usr_local_go() {
    ln -s /usr/local/go/bin/go /usr/bin/go
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt
}

install_golang_from_github() {
    if [[ $ARCH == x86_64 ]]; then
        GO_URL="https://go.dev/dl/go1.24.11.linux-amd64.tar.gz"
    else
        GO_URL="https://go.dev/dl/go1.24.11.linux-arm64.tar.gz"
    fi

    GO_FILE=$(basename $GO_URL)

    # Download
    rm -f "/tmp/$GO_FILE"
    curl -L -o "/tmp/$GO_FILE" "$GO_URL"

    # Install
    cd /usr/local
    rm -rf ./go
    tar xfz /tmp/"$GO_FILE"
    cd -

    link_golang_usr_local_go
}

install_clang_os_packages() {
    wait_for_apt_locks
    # Use centralized Clang installation script
    if [ -f "$INSTALL_SCRIPT" ]; then
        bash "$INSTALL_SCRIPT"
    else
        die "Centralized Clang install script not found at: $INSTALL_SCRIPT"
    fi
}

install_gcc11_os_packages() {
    wait_for_apt_locks
    apt-get install -y gcc-11
}

install_gcc12_os_packages() {
    wait_for_apt_locks
    apt-get install -y gcc-12
}

remove_llvm_os_packages() {
    wait_for_apt_locks
    # Remove previous clang versions to ensure clean installation
    apt-get remove -y clang-14 clangd-14 lld-14 llvm-14 || true
    apt-get remove -y clang-18 clangd-18 lld-18 llvm-18 || true
    apt-get remove -y clang-19 clangd-19 lld-19 llvm-19 || true
    apt-get --purge autoremove -y
}

remove_golang_os_packages() {
    wait_for_apt_locks
    apt-get remove -y golang golang-go
    apt-get --purge autoremove -y
}

install_libzstd_os_packages() {
    case $ID in
        "ubuntu")
            wait_for_apt_locks
            apt-get install -y libzstd-dev
            ;;
        "almalinux")
            yum install -y libzstd-devel
            ;;
        *)
            echo "Unsupported OS: $ID"
            exit 1
            ;;
    esac
}

# Main logic.

KERNEL=$(uname -r)

# shellcheck source=/dev/null
# See SC1091
. /etc/os-release

if [[ $ID == "ubuntu" ]]; then
    export DEBIAN_FRONTEND=noninteractive

    disable_unattended_upgrades

    wait_for_apt_locks
    apt-get update
    # apt-get dist-upgrade -y
    # apt-get --purge autoremove -y

    # Clean up old LLVM packages before fresh installation
    remove_llvm_os_packages

    remove_golang_alternatives
    remove_golang_os_packages
    remove_golang_usr_bin_files

    case $VERSION_CODENAME in
        "focal")
            # apt-get install -y libtinfo5
            install_clang_os_packages
            install_golang_from_github
            ;;
        "jammy")
            if [[ "$KERNEL" == *"5.19"* ]]; then
                # needed by instrumentation tests
                install_gcc11_os_packages
                install_gcc12_os_packages
            fi
            install_clang_os_packages
            install_golang_from_github
            ;;
        "noble")
            install_clang_os_packages
            install_golang_from_github
            ;;
        "lunar")
            install_clang_os_packages
            install_golang_from_github
            ;;
        "mantic")
            install_clang_os_packages
            install_golang_from_github
            ;;
        *)
            echo "Unsupported Ubuntu version: $VERSION_CODENAME"
            exit 1
            ;;
    esac
fi

if [[ $ID == "almalinux" ]]; then
    remove_golang_alternatives
    remove_golang_usr_bin_files
    install_golang_from_github
fi

# for static builds libelf might require libzstd
install_libzstd_os_packages
