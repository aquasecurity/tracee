#!/bin/bash -e

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

disable_unattended_upgrades() {
    # This is a pain point. Make sure to always disable anything touching the
    # dpkg database, otherwise it will fail with locking errors.
    systemctl stop unattended-upgrades || true
    systemctl disable --now unattended-upgrades || true
    apt-get remove -y --purge unattended-upgrades || true
    apt-get remove -y --purge ubuntu-advantage-tools || true
}

wait_for_apt_locks() {
    local lock_frontend="/var/lib/dpkg/lock-frontend"
    local lock_lists="/var/lib/apt/lists/lock"
    local lock_archives="/var/cache/apt/archives/lock"
    local timeout=20
    local wait_interval=2
    local elapsed=0

    while : ; do
        if ! fuser $lock_frontend >/dev/null 2>&1 &&
           ! fuser $lock_lists >/dev/null 2>&1 &&
           ! fuser $lock_archives >/dev/null 2>&1; then
            echo "All apt locks are free."
            break
        fi

        if (( elapsed >= timeout )); then
            echo "Timed out waiting for apt locks to be released. Attempting to kill locking processes."
            fuser -k -SIGQUIT $lock_frontend >/dev/null 2>&1 || true
            fuser -k -SIGQUIT $lock_lists >/dev/null 2>&1 || true
            fuser -k -SIGQUIT $lock_archives >/dev/null 2>&1 || true
            sleep 2 # Give some time for processes to terminate gracefully
            fuser -k -SIGKILL $lock_frontend >/dev/null 2>&1 || true
            fuser -k -SIGKILL $lock_lists >/dev/null 2>&1 || true
            fuser -k -SIGKILL $lock_archives >/dev/null 2>&1 || true
            echo "Forced removal of processes locking apt. System may be in an inconsistent state."
            break
        fi

        echo "Waiting for other software managers to finish..."
        sleep $wait_interval
        ((elapsed += wait_interval))
    done
}


remove_llvm_alternatives() {
    update-alternatives --remove-all cc || true
    update-alternatives --remove-all clang || true
    update-alternatives --remove-all clang++ || true
    update-alternatives --remove-all llc || true
    update-alternatives --remove-all lld || true
    update-alternatives --remove-all clangd || true
    update-alternatives --remove-all clang-format || true
    update-alternatives --remove-all llvm-strip || true
    update-alternatives --remove-all llvm-config || true
    update-alternatives --remove-all ld.lld || true
    update-alternatives --remove-all llvm-ar || true
    update-alternatives --remove-all llvm-nm || true
    update-alternatives --remove-all llvm-objcopy || true
    update-alternatives --remove-all llvm-objdump || true
    update-alternatives --remove-all llvm-readelf || true
    update-alternatives --remove-all opt || true
}

update_llvm_alternatives() {
    version=14
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${version} ${version}0 \
        --slave /usr/bin/clang++ clang++ /usr/bin/clang++-${version} \
        --slave /usr/bin/clangd clangd /usr/bin/clangd-${version} \
        --slave /usr/bin/clang-format clang-format /usr/bin/clang-format-${version} \
        --slave /usr/bin/lld lld /usr/bin/lld-${version} \
        --slave /usr/bin/llc llc /usr/bin/llc-${version} \
        --slave /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-${version} \
        --slave /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${version} \
        --slave /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-${version} \
        --slave /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-${version} \
        --slave /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-${version} \
        --slave /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-${version} \
        --slave /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-${version} \
        --slave /usr/bin/llvm-readelf llvm-readelf /usr/bin/llvm-readelf-${version} \
        --slave /usr/bin/opt opt /usr/bin/opt-${version} \
        --slave /usr/bin/cc cc /usr/bin/clang-${version}
}

remove_golang_alternatives() {
    update-alternatives --remove-all go || true
    update-alternatives --remove-all gofmt || true
}

remove_llvm_usr_bin_files() {
    rm -f /usr/bin/clang*
    rm -f /usr/bin/clang++*
    rm -f /usr/bin/clangd*
    rm -f /usr/bin/clang-format*

    rm -f /usr/bin/lld*
    rm -f /usr/bin/llc*
    rm -f /usr/bin/llvm-strip*
    rm -f /usr/bin/llvm-config*
    rm -f /usr/bin/ld.lld*
    rm -f /usr/bin/llvm-ar*
    rm -f /usr/bin/llvm-nm*
    rm -f /usr/bin/llvm-objcopy*
    rm -f /usr/bin/llvm-objdump*
    rm -f /usr/bin/llvm-readelf*
    rm -f /usr/bin/opt
    rm -f /usr/bin/cc
}

remove_golang_usr_bin_files() {
    rm -f /usr/bin/go
    rm -f /usr/bin/gofmt
}

link_golang_usr_local_go() {
    ln -s /usr/local/go/bin/go /usr/bin/go
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt
}

link_llvm_usr_local_clang() {
    ln -s /usr/local/clang/bin/clang /usr/bin/clang
    ln -s /usr/local/clang/bin/clang++ /usr/bin/clang++
    ln -s /usr/local/clang/bin/clangd /usr/bin/clangd
    ln -s /usr/local/clang/bin/clang-format /usr/bin/clang-format
    ln -s /usr/local/clang/bin/lld /usr/bin/lld
    ln -s /usr/local/clang/bin/llc /usr/bin/llc
    ln -s /usr/local/clang/bin/llvm-strip /usr/bin/llvm-strip
    ln -s /usr/local/clang/bin/llvm-config /usr/bin/llvm-config
    ln -s /usr/local/clang/bin/ld.lld /usr/bin/ld.lld
    ln -s /usr/local/clang/bin/llvm-ar /usr/bin/llvm-ar
    ln -s /usr/local/clang/bin/llvm-nm /usr/bin/llvm-nm
    ln -s /usr/local/clang/bin/llvm-objcopy /usr/bin/llvm-objcopy
    ln -s /usr/local/clang/bin/llvm-objdump /usr/bin/llvm-objdump
    ln -s /usr/local/clang/bin/llvm-readelf /usr/bin/llvm-readelf
    ln -s /usr/local/clang/bin/opt /usr/bin/opt
}

install_clang_from_github() {
    LLVM_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/"

    if [[ $ARCH == x86_64 ]]; then
        LLVM_URL=$LLVM_URL"clang+llvm-14.0.6-x86_64-linux-gnu-rhel-8.4.tar.xz"
    else
        LLVM_URL=$LLVM_URL"clang+llvm-14.0.6-aarch64-linux-gnu.tar.xz"
    fi

    LLVM_FILE=$(echo $(basename $LLVM_URL))
    LLVM_DIR=$(echo $LLVM_FILE | sed 's:.tar.xz::g')

    # Download
    rm -f "/tmp/$LLVM_FILE"
    curl -L -o "/tmp/$LLVM_FILE" "$LLVM_URL"

    # Install
    cd /usr/local
    rm -rf ./clang
    tar xfJ /tmp/$LLVM_FILE
    mv $LLVM_DIR ./clang
    cd -

    link_llvm_usr_local_clang
}

install_golang_from_github() {
    if [[ $ARCH == x86_64 ]]; then
        GO_URL="https://go.dev/dl/go1.21.6.linux-amd64.tar.gz"
    else
        GO_URL="https://go.dev/dl/go1.21.6.linux-arm64.tar.gz"
    fi

    GO_FILE=$(echo $(basename $GO_URL))

    # Download
    rm -f "/tmp/$GO_FILE"
    curl -L -o "/tmp/$GO_FILE" "$GO_URL"

    # Install
    cd /usr/local
    rm -rf ./go
    tar xfz /tmp/$GO_FILE
    cd -

    link_golang_usr_local_go
}

install_clang_os_packages() {
    apt-get install -y llvm-14 clang-14 clangd-14 lld-14
    update_llvm_alternatives
}

install_gcc11_os_packages() {
    apt-get install -y gcc-11
}

install_gcc12_os_packages() {
    apt-get install -y gcc-12
}

remove_llvm_os_packages() {
    apt-get remove -y clang-12 clangd-12 lld-12 llvm-12 || true
    apt-get remove -y clang-13 clangd-13 lld-13 llvm-13 || true
    apt-get remove -y clang-14 clangd-14 lld-14 llvm-14 || true
    apt-get --purge autoremove -y
}

remove_golang_os_packages() {
    apt-get remove -y golang golang-go
    apt-get --purge autoremove -y
}

# Main logic.

# Note: I left commented out the commands that would (re)install clang-14. This
# shows how an eventual upgrade to clang-15 (and on) would look like.

KERNEL=$(uname -r)

. /etc/os-release

if [[ $ID == "ubuntu" ]]; then
    export DEBIAN_FRONTEND=noninteractive

    disable_unattended_upgrades
    wait_for_apt_locks

    apt-get update
    # apt-get dist-upgrade -y
    # apt-get --purge autoremove -y

    # remove_llvm_alternatives
    # remove_llvm_os_packages
    # remove_llvm_usr_bin_files

    remove_golang_alternatives
    remove_golang_os_packages
    remove_golang_usr_bin_files

    case $VERSION_CODENAME in
    "focal")
        # apt-get install -y libtinfo5
        # install_clang_from_github
        install_golang_from_github
        ;;
    "jammy")
        if [[ "$KERNEL" == *"5.19"* ]]; then
            # needed by instrumentation tests
            install_gcc11_os_packages
            install_gcc12_os_packages
        fi
        #install_clang_os_packages
        install_golang_from_github
        ;;
    "lunar")
        #install_clang_os_packages
        install_golang_from_github
        ;;
    "mantic")
        #install_clang_os_packages
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
