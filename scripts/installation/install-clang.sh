#!/bin/bash

# Centralized Clang installation script for Tracee
# Supports Alpine Linux, Ubuntu/Debian, and CentOS/RHEL environments

set -euo pipefail

# Source lib.sh for consistent logging and utilities
__LIB_DIR="${0%/*}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - single source of truth for Clang version
CLANG_VERSION=19

# List of all LLVM/Clang tools we manage
CLANG_TOOLS="cc clang clang++ llc lld clangd clang-format llvm-strip llvm-config ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf opt"

# Detect environment
detect_environment() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/debian_version ]; then
        echo "ubuntu"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        echo "centos"
    elif [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case "${ID}" in
            centos | rhel | fedora | rocky | almalinux | amzn)
                echo "centos"
                ;;
            *)
                if [[ "${ID_LIKE:-}" == *"rhel"* ]] || [[ "${ID_LIKE:-}" == *"centos"* ]] || [[ "${ID_LIKE:-}" == *"fedora"* ]]; then
                    echo "centos"
                else
                    die "Unsupported operating system for Clang installation: ${ID}"
                fi
                ;;
        esac
    else
        die "Unsupported operating system for Clang installation"
    fi
}

# Alpine installation and symlink setup
install_clang_alpine() {
    info "Installing Clang ${CLANG_VERSION} on Alpine Linux"

    # Verify Alpine-specific commands are available
    require_cmds apk ln rm

    apk add --no-cache \
        clang${CLANG_VERSION} \
        clang${CLANG_VERSION}-extra-tools \
        llvm${CLANG_VERSION} \
        musl-dev \
        libc6-compat

    setup_alpine_symlinks
}

# Set up symlinks for Alpine (no update-alternatives available)
setup_alpine_symlinks() {
    info "Setting up Clang ${CLANG_VERSION} symlinks"

    # Remove existing symlinks (one per line for readability)
    for tool in ${CLANG_TOOLS}; do
        rm -f "/usr/bin/${tool}"
    done

    # Create new symlinks
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang /usr/bin/cc
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang /usr/bin/clang
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang++ /usr/bin/clang++
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llc /usr/bin/llc
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/lld /usr/bin/lld
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clangd /usr/bin/clangd
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang-format /usr/bin/clang-format
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-strip /usr/bin/llvm-strip
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-config /usr/bin/llvm-config
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/lld /usr/bin/ld.lld
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-ar /usr/bin/llvm-ar
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-nm /usr/bin/llvm-nm
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-objcopy /usr/bin/llvm-objcopy
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-objdump /usr/bin/llvm-objdump
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-readelf /usr/bin/llvm-readelf
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/opt /usr/bin/opt
}

# Add LLVM APT repository for newer Clang versions
add_llvm_apt_repo() {
    info "Adding LLVM APT repository for Clang ${CLANG_VERSION}"

    require_cmds apt-get curl

    # Install prerequisites
    apt-get update
    apt-get install -y wget gnupg software-properties-common

    # Add LLVM GPG key
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc > /dev/null

    # Detect Ubuntu codename
    local codename
    if command -v lsb_release > /dev/null 2>&1; then
        codename=$(lsb_release -cs)
    elif [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        codename="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
    fi

    if [[ -z "${codename}" ]]; then
        warn "Could not detect Ubuntu codename, using 'jammy'"
        codename="jammy"
    fi

    info "Detected Ubuntu codename: ${codename}"

    # Add LLVM repository
    echo "deb http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${CLANG_VERSION} main" > /etc/apt/sources.list.d/llvm.list
    echo "deb-src http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${CLANG_VERSION} main" >> /etc/apt/sources.list.d/llvm.list

    apt-get update
}

# Ubuntu/Debian installation
install_clang_ubuntu() {
    info "Installing Clang ${CLANG_VERSION} on Ubuntu/Debian"

    # Verify Ubuntu-specific commands are available
    require_cmds apt-get update-alternatives ln rm

    # Add LLVM repository for newer Clang versions
    add_llvm_apt_repo

    # Install base LLVM and Clang packages
    apt-get install -y \
        llvm-${CLANG_VERSION} \
        clang-${CLANG_VERSION} \
        clang-tools-${CLANG_VERSION}

    # Try to install clang-format-19 directly (separate package)
    if apt-get install -y clang-format-${CLANG_VERSION}; then
        info "clang-format-${CLANG_VERSION} installed successfully"
    else
        warn "clang-format-${CLANG_VERSION} package not available"
    fi

    setup_ubuntu_alternatives
}

# Set up update-alternatives for Ubuntu/Debian
setup_ubuntu_alternatives() {
    info "Setting up update-alternatives for Clang ${CLANG_VERSION}"

    # Remove all existing alternatives to avoid conflicts
    for tool in ${CLANG_TOOLS}; do
        update-alternatives --remove-all "${tool}" 2> /dev/null || true
    done

    # Check if current clang is already the target version
    if command -v clang > /dev/null 2>&1; then
        current_version=$(clang --version | grep -o "clang version [0-9]\+" | head -1 | grep -o "[0-9]\+")
        if [ "$current_version" = "$CLANG_VERSION" ]; then
            info "Default clang is already version ${CLANG_VERSION}"
            return
        fi
    fi

    # Set up clang alternative
    if [ -f /usr/bin/clang-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${CLANG_VERSION} $((CLANG_VERSION * 10)) \
            --slave /usr/bin/cc cc /usr/bin/clang-${CLANG_VERSION}
    fi

    # Set up clang++ alternative if available
    if [ -f /usr/bin/clang++-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${CLANG_VERSION} $((CLANG_VERSION * 10))
    fi

    # Set up clang-format alternative if available
    if [ -f /usr/bin/clang-format-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-${CLANG_VERSION} $((CLANG_VERSION * 10))
    fi
}

# CentOS/RHEL installation
install_clang_centos() {
    info "Installing Clang ${CLANG_VERSION} on CentOS/RHEL"

    # Detect package manager
    local pkg_manager
    if command -v dnf > /dev/null 2>&1; then
        pkg_manager="dnf"
    elif command -v yum > /dev/null 2>&1; then
        pkg_manager="yum"
    else
        die "No supported package manager found (dnf or yum required)"
    fi

    require_cmds "${pkg_manager}" ln rm

    # Detect RHEL version
    local rhel_version
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        rhel_version="${VERSION_ID%%.*}"
    else
        rhel_version="9"
    fi

    info "Detected RHEL version: ${rhel_version}"

    # Try to install specific Clang version
    # Priority: 1) LLVM pre-built binaries (exact version)
    #           2) COPR versioned packages
    #           3) System packages (fallback, may not be version 19)

    local installed=false

    # First try: LLVM pre-built binaries (guarantees exact version)
    info "Trying to install Clang ${CLANG_VERSION} from LLVM pre-built binaries"
    if install_clang_from_llvm_release "${CLANG_VERSION}"; then
        installed=true
    fi

    # Second try: COPR versioned packages
    if [[ "${installed}" != "true" ]]; then
        add_llvm_yum_repo "${pkg_manager}" "${rhel_version}"

        # Try versioned packages from COPR (format: clang19)
        if ${pkg_manager} install -y \
            "clang${CLANG_VERSION}" \
            "clang${CLANG_VERSION}-tools-extra" \
            "llvm${CLANG_VERSION}" \
            "lld${CLANG_VERSION}" 2> /dev/null; then
            installed=true
            info "Installed Clang ${CLANG_VERSION} from COPR"
        fi
    fi

    # Third try: versioned packages with dash (format: clang-19)
    if [[ "${installed}" != "true" ]]; then
        if ${pkg_manager} install -y \
            "clang-${CLANG_VERSION}" \
            "clang-tools-extra-${CLANG_VERSION}" \
            "llvm-${CLANG_VERSION}" \
            "lld-${CLANG_VERSION}" 2> /dev/null; then
            installed=true
            info "Installed Clang ${CLANG_VERSION} from repository"
        fi
    fi

    # Fall back to system packages (may not be version 19)
    if [[ "${installed}" != "true" ]]; then
        warn "Clang ${CLANG_VERSION} not available, installing system default"
        if ${pkg_manager} install -y \
            clang \
            clang-tools-extra \
            llvm \
            lld; then
            installed=true
        fi
    fi

    if [[ "${installed}" != "true" ]]; then
        die "Failed to install Clang packages"
    fi

    setup_centos_symlinks

    # Verify the installed version and warn if it doesn't match
    if command -v clang > /dev/null 2>&1; then
        local installed_version
        installed_version=$(clang --version | grep -o "clang version [0-9]\+" | head -1 | grep -o "[0-9]\+")
        if [[ "${installed_version}" != "${CLANG_VERSION}" ]]; then
            warn "Installed Clang version ${installed_version} instead of requested version ${CLANG_VERSION}"
            warn "This is expected on RHEL 9 where Clang ${CLANG_VERSION} pre-built binaries are not available"
            warn "Clang ${installed_version} should be compatible for most use cases"
        fi
    fi
}

# Install Clang from LLVM pre-built release binaries
install_clang_from_llvm_release() {
    local version="$1"
    local arch
    arch=$(uname -m)

    require_cmds curl tar xz

    # LLVM 19+ only provides pre-built binaries for aarch64 Linux
    # For x86_64, we need to use older versions or system packages
    if [[ "${arch}" == "x86_64" ]] && [[ "${version}" -ge 19 ]]; then
        warn "LLVM ${version} pre-built binaries not available for x86_64 Linux"
        return 1
    fi

    # Build the download URL based on architecture
    local llvm_version="${version}.1.8"
    local llvm_url=""

    if [[ "${arch}" == "aarch64" ]]; then
        llvm_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-${llvm_version}/clang+llvm-${llvm_version}-aarch64-linux-gnu.tar.xz"
    elif [[ "${arch}" == "x86_64" ]]; then
        # For x86_64, use Ubuntu 18.04 build (available for LLVM 18 and earlier)
        llvm_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-${llvm_version}/clang+llvm-${llvm_version}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
    else
        warn "LLVM pre-built binaries not available for architecture: ${arch}"
        return 1
    fi

    info "Downloading LLVM ${llvm_version} from GitHub releases..."

    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064  # We want tmpdir expanded now
    trap "rm -rf '${tmpdir}'" RETURN

    if ! curl -fsSL -o "${tmpdir}/llvm.tar.xz" "${llvm_url}"; then
        warn "Failed to download LLVM ${llvm_version}"
        return 1
    fi

    info "Extracting LLVM to /usr/local/llvm-${version}..."
    mkdir -p "/usr/local/llvm-${version}"
    tar -xf "${tmpdir}/llvm.tar.xz" -C "/usr/local/llvm-${version}" --strip-components=1

    # Create symlinks
    local llvm_bin="/usr/local/llvm-${version}/bin"
    if [[ -f "${llvm_bin}/clang" ]]; then
        ln -sf "${llvm_bin}/clang" /usr/bin/clang
        ln -sf "${llvm_bin}/clang" /usr/bin/cc
        ln -sf "${llvm_bin}/clang++" /usr/bin/clang++
        ln -sf "${llvm_bin}/clang-format" /usr/bin/clang-format
        ln -sf "${llvm_bin}/lld" /usr/bin/lld
        ln -sf "${llvm_bin}/ld.lld" /usr/bin/ld.lld
        ln -sf "${llvm_bin}/llvm-ar" /usr/bin/llvm-ar
        ln -sf "${llvm_bin}/llvm-nm" /usr/bin/llvm-nm
        ln -sf "${llvm_bin}/llvm-strip" /usr/bin/llvm-strip
        ln -sf "${llvm_bin}/llvm-objcopy" /usr/bin/llvm-objcopy
        ln -sf "${llvm_bin}/llc" /usr/bin/llc
        ln -sf "${llvm_bin}/opt" /usr/bin/opt
        ln -sf "${llvm_bin}/llvm-config" /usr/bin/llvm-config
        info "LLVM ${llvm_version} installed successfully from pre-built binaries"
        return 0
    else
        warn "LLVM binaries not found after extraction"
        return 1
    fi
}

# Add LLVM YUM/DNF repository for CentOS/RHEL
add_llvm_yum_repo() {
    local pkg_manager="$1"
    local rhel_version="$2"

    info "Adding LLVM repository for Clang ${CLANG_VERSION} on RHEL ${rhel_version}"

    # Install prerequisites
    ${pkg_manager} install -y yum-utils 2> /dev/null || true

    # Try multiple COPR repositories for LLVM
    # The fedora-llvm-team provides llvm-compat-packages with specific versions
    local repo_urls=(
        "https://download.copr.fedorainfracloud.org/results/@fedora-llvm-team/llvm-compat-packages/epel-${rhel_version}-\$basearch/"
        "https://download.copr.fedorainfracloud.org/results/@fedora-llvm-team/llvm-snapshots/epel-${rhel_version}-\$basearch/"
    )

    local repo_added=false
    for url in "${repo_urls[@]}"; do
        cat > /etc/yum.repos.d/llvm-${CLANG_VERSION}.repo << EOF
[llvm-toolchain-${CLANG_VERSION}]
name=LLVM Toolchain ${CLANG_VERSION}
baseurl=${url}
enabled=1
gpgcheck=0
priority=10
EOF
        if ${pkg_manager} makecache 2> /dev/null; then
            repo_added=true
            info "Successfully added LLVM repository"
            break
        fi
    done

    if [[ "${repo_added}" != "true" ]]; then
        warn "Could not add LLVM COPR repository, will try system packages"
        rm -f /etc/yum.repos.d/llvm-${CLANG_VERSION}.repo
    fi
}

# Set up symlinks for CentOS/RHEL
setup_centos_symlinks() {
    info "Setting up Clang ${CLANG_VERSION} symlinks for CentOS/RHEL"

    # Check if versioned binaries exist, otherwise use unversioned
    local clang_bin
    if [[ -f /usr/bin/clang-${CLANG_VERSION} ]]; then
        clang_bin="/usr/bin/clang-${CLANG_VERSION}"
    elif [[ -f /usr/bin/clang ]]; then
        clang_bin="/usr/bin/clang"
        info "Using unversioned clang binary"
        return
    else
        die "Clang binary not found"
    fi

    # Create symlinks for versioned binaries
    for tool in ${CLANG_TOOLS}; do
        rm -f "/usr/bin/${tool}"
    done

    # Create symlinks for clang
    ln -sf "${clang_bin}" /usr/bin/clang
    ln -sf "${clang_bin}" /usr/bin/cc

    # Create symlinks for versioned tools
    local versioned_tools=(
        "clang++"
        "clang-format"
        "lld"
        "llvm-strip"
        "llvm-ar"
        "llvm-nm"
        "llvm-objcopy"
        "llc"
        "opt"
        "llvm-config"
    )

    for tool in "${versioned_tools[@]}"; do
        if [[ -f "/usr/bin/${tool}-${CLANG_VERSION}" ]]; then
            ln -sf "/usr/bin/${tool}-${CLANG_VERSION}" "/usr/bin/${tool}"
        fi
    done

    # Special case: ld.lld symlink
    if [[ -f "/usr/bin/lld-${CLANG_VERSION}" ]]; then
        ln -sf "/usr/bin/lld-${CLANG_VERSION}" /usr/bin/ld.lld
    fi
}

# Verify installation
verify_installation() {
    info "Verifying Clang installation"

    # Use require_cmds to verify essential tools are available
    require_cmds clang

    # Check clang version
    if command -v clang > /dev/null 2>&1; then
        clang_version_output=$(clang --version 2> /dev/null | head -1 || echo "")
        info "Clang: $clang_version_output"
    else
        warn "clang command not found"
    fi

    # Check clang-format version if available
    if command -v clang-format > /dev/null 2>&1; then
        clang_format_version_output=$(clang-format --version 2> /dev/null | head -1 || echo "")
        info "clang-format: $clang_format_version_output"
    else
        warn "clang-format command not found"
    fi
}

# Main installation logic
main() {
    info "Starting Clang ${CLANG_VERSION} installation for Tracee"

    OS_TYPE=$(detect_environment)
    info "Detected environment: $OS_TYPE"

    case "$OS_TYPE" in
        "alpine")
            install_clang_alpine
            ;;
        "ubuntu")
            install_clang_ubuntu
            ;;
        "centos")
            install_clang_centos
            ;;
        *)
            die "Unsupported operating system: $OS_TYPE"
            ;;
    esac

    verify_installation
    info "Clang ${CLANG_VERSION} installation completed successfully!"
}

# Run main function
main
