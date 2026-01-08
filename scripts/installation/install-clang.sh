#!/bin/bash

# Centralized Clang installation script for Tracee
# Supports Alpine Linux, Ubuntu/Debian, and CentOS/RHEL environments

set -euo pipefail

# Source lib.sh for consistent logging and utilities
__LIB_DIR="${0%/*}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - single source of truth for Clang version
#
# IMPORTANT: When updating CLANG_VERSION, you must also update LLVM_FULL_VERSION
# to match the latest point release available at:
#   https://github.com/llvm/llvm-project/releases
#
CLANG_VERSION=19
LLVM_FULL_VERSION="19.1.7"

# Path to LLVM release signing GPG key for signature verification
# Official source: https://llvm.org/release-keys.asc
# See: https://github.com/llvm/llvm-project/releases (verification instructions)
SCRIPT_DIR="${0%/*}"
LLVM_GPG_KEY_FILE="${SCRIPT_DIR}/keys/llvm-release-signing-key.asc"

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

    # Fourth try: full version format (format: clang-19.1.7)
    if [[ "${installed}" != "true" ]]; then
        if ${pkg_manager} install -y \
            "clang-${LLVM_FULL_VERSION}" \
            "clang-tools-extra-${LLVM_FULL_VERSION}" \
            "llvm-${LLVM_FULL_VERSION}" \
            "lld-${LLVM_FULL_VERSION}" 2> /dev/null; then
            installed=true
            info "Installed Clang ${LLVM_FULL_VERSION} from repository (full version format)"
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

    # Store the clang binary path before setting up symlinks
    # Use -e to check for both files and symlinks
    local installed_clang_bin=""
    if [[ -e /usr/bin/clang-${LLVM_FULL_VERSION} ]]; then
        installed_clang_bin="/usr/bin/clang-${LLVM_FULL_VERSION}"
    elif [[ -e /usr/bin/clang-${CLANG_VERSION} ]]; then
        installed_clang_bin="/usr/bin/clang-${CLANG_VERSION}"
    elif [[ -e /usr/bin/clang ]]; then
        installed_clang_bin="/usr/bin/clang"
    fi

    setup_centos_symlinks

    # Check for conflicting clang installations in /usr/local/bin (often takes precedence in PATH)
    # Replace it with a symlink to our installed version in /usr/bin
    if [[ -e /usr/local/bin/clang ]]; then
        local local_clang_version
        local_clang_version=$(/usr/local/bin/clang --version 2> /dev/null | grep -o "clang version [0-9]\+" | head -1 | grep -o "[0-9]\+" || echo "")
        if [[ -n "${local_clang_version}" ]] && [[ "${local_clang_version}" != "${CLANG_VERSION}" ]]; then
            info "Found Clang ${local_clang_version} in /usr/local/bin/clang, replacing with symlink to Clang ${CLANG_VERSION} from /usr/bin"
            rm -f /usr/local/bin/clang
            # Use /usr/bin/clang which should now point to our installed version
            if [[ -e /usr/bin/clang ]]; then
                ln -sf /usr/bin/clang /usr/local/bin/clang
            elif [[ -n "${installed_clang_bin}" ]] && [[ -e "${installed_clang_bin}" ]]; then
                ln -sf "${installed_clang_bin}" /usr/local/bin/clang
            fi
            # Also update cc if it exists
            if [[ -e /usr/local/bin/cc ]]; then
                rm -f /usr/local/bin/cc
                if [[ -e /usr/bin/cc ]]; then
                    ln -sf /usr/bin/cc /usr/local/bin/cc
                elif [[ -n "${installed_clang_bin}" ]] && [[ -e "${installed_clang_bin}" ]]; then
                    ln -sf "${installed_clang_bin}" /usr/local/bin/cc
                fi
            fi
        fi
    fi

    # Verify the installed version using the binary we just installed, not PATH
    # Use /usr/bin/clang after setup, or fall back to installed_clang_bin
    local verify_bin=""
    if [[ -e /usr/bin/clang ]]; then
        verify_bin="/usr/bin/clang"
    elif [[ -n "${installed_clang_bin}" ]] && [[ -e "${installed_clang_bin}" ]]; then
        verify_bin="${installed_clang_bin}"
    fi

    if [[ -n "${verify_bin}" ]]; then
        local installed_version
        installed_version=$("${verify_bin}" --version | grep -o "clang version [0-9]\+" | head -1 | grep -o "[0-9]\+")
        if [[ "${installed_version}" != "${CLANG_VERSION}" ]]; then
            warn "Installed Clang version ${installed_version} instead of requested version ${CLANG_VERSION}"
            if [[ "${rhel_version}" == "9" ]]; then
                warn "This is expected on RHEL 9 where Clang ${CLANG_VERSION} pre-built binaries are not available"
            elif [[ "${rhel_version}" == "8" ]]; then
                warn "This is expected on RHEL 8 where Clang ${CLANG_VERSION} may not be available in default repositories"
            fi
            warn "Clang ${installed_version} should be compatible for most use cases"
        else
            info "Successfully installed and configured Clang ${installed_version}"
        fi
    fi
}

# Install Clang from LLVM pre-built release binaries
install_clang_from_llvm_release() {
    local version="$1"
    local arch
    arch=$(uname -m)

    require_cmds curl tar xz gpg

    # LLVM 19+ only provides pre-built binaries for aarch64 Linux
    # For x86_64, we need to use older versions or system packages
    if [[ "${arch}" == "x86_64" ]] && [[ "${version}" -ge 19 ]]; then
        warn "LLVM ${version} pre-built binaries not available for x86_64 Linux"
        return 1
    fi

    # Check that the GPG key file exists for signature verification
    if [[ ! -f "${LLVM_GPG_KEY_FILE}" ]] || [[ $(wc -l < "${LLVM_GPG_KEY_FILE}") -lt 10 ]]; then
        warn "LLVM GPG signing key not found or incomplete: ${LLVM_GPG_KEY_FILE}"
        warn "Download the key with: gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 44F2485E45D59042"
        warn "Then export: gpg --armor --export 44F2485E45D59042 > ${LLVM_GPG_KEY_FILE}"
        return 1
    fi

    # Build the download URL based on architecture
    # Use the global LLVM_FULL_VERSION for the complete version string
    local llvm_version="${LLVM_FULL_VERSION}"
    local llvm_url=""
    local tarball_name=""

    if [[ "${arch}" == "aarch64" ]]; then
        tarball_name="clang+llvm-${llvm_version}-aarch64-linux-gnu.tar.xz"
    elif [[ "${arch}" == "x86_64" ]]; then
        # For x86_64, use Ubuntu 18.04 build (available for LLVM 18 and earlier)
        tarball_name="clang+llvm-${llvm_version}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
    else
        warn "LLVM pre-built binaries not available for architecture: ${arch}"
        return 1
    fi

    llvm_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-${llvm_version}/${tarball_name}"

    info "Downloading LLVM ${llvm_version} from GitHub releases..."

    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064  # We want tmpdir expanded now
    trap "rm -rf '${tmpdir}'" RETURN

    # Download the tarball
    if ! curl -fsSL -o "${tmpdir}/llvm.tar.xz" "${llvm_url}"; then
        warn "Failed to download LLVM ${llvm_version}"
        return 1
    fi

    # Download the signature file
    info "Downloading LLVM signature..."
    if ! curl -fsSL -o "${tmpdir}/llvm.tar.xz.sig" "${llvm_url}.sig"; then
        warn "Failed to download LLVM signature file"
        return 1
    fi

    # Verify the GPG signature before extraction
    if ! verify_gpg_signature "${tmpdir}/llvm.tar.xz" "${tmpdir}/llvm.tar.xz.sig" "${LLVM_GPG_KEY_FILE}" "LLVM ${llvm_version}"; then
        error "Aborting LLVM installation due to signature verification failure"
        return 1
    fi

    # Signature verified, proceed with extraction
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
    # On RHEL/AlmaLinux, packages may create binaries with full version format
    # Use -e to check for both files and symlinks
    local clang_bin
    if [[ -e /usr/bin/clang-${LLVM_FULL_VERSION} ]]; then
        clang_bin="/usr/bin/clang-${LLVM_FULL_VERSION}"
        info "Found Clang binary with full version: ${LLVM_FULL_VERSION}"
    elif [[ -e /usr/bin/clang-${CLANG_VERSION} ]]; then
        clang_bin="/usr/bin/clang-${CLANG_VERSION}"
        info "Found Clang binary with major version: ${CLANG_VERSION}"
    elif [[ -e /usr/bin/clang ]]; then
        clang_bin="/usr/bin/clang"
        info "Using unversioned clang binary"
    else
        # Debug: list what clang binaries actually exist
        info "Debug: Searching for clang binaries..."
        ls -la /usr/bin/clang* 2> /dev/null | head -10 || true
        die "Clang binary not found"
    fi

    # Check if update-alternatives is available (some RHEL systems have it)
    if command -v update-alternatives > /dev/null 2>&1; then
        info "update-alternatives found, using it to configure Clang ${CLANG_VERSION}"

        # Remove all existing alternatives to avoid conflicts
        for tool in ${CLANG_TOOLS}; do
            update-alternatives --remove-all "${tool}" 2> /dev/null || true
        done

        # Set up clang alternative with high priority
        local priority=$((CLANG_VERSION * 100))  # Higher priority than default
        if [[ -e "${clang_bin}" ]]; then
            update-alternatives --install /usr/bin/clang clang "${clang_bin}" "${priority}" \
                --slave /usr/bin/cc cc "${clang_bin}" 2> /dev/null || true
            # Set it as the default
            update-alternatives --set clang "${clang_bin}" 2> /dev/null || true
        fi
    else
        # No update-alternatives, use direct symlinks
        info "update-alternatives not available, using direct symlinks"

        # Remove any existing symlinks that might conflict
        for tool in ${CLANG_TOOLS}; do
            rm -f "/usr/bin/${tool}"
        done

        # Create symlinks for clang
        ln -sf "${clang_bin}" /usr/bin/clang
        ln -sf "${clang_bin}" /usr/bin/cc
    fi

    # Set up symlinks/alternatives for versioned tools
    # Try full version first, then major version, then unversioned
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

    local priority=$((CLANG_VERSION * 100))

    for tool in "${versioned_tools[@]}"; do
        local tool_bin=""
        if [[ -e "/usr/bin/${tool}-${LLVM_FULL_VERSION}" ]]; then
            tool_bin="/usr/bin/${tool}-${LLVM_FULL_VERSION}"
        elif [[ -e "/usr/bin/${tool}-${CLANG_VERSION}" ]]; then
            tool_bin="/usr/bin/${tool}-${CLANG_VERSION}"
        fi

        if [[ -n "${tool_bin}" ]]; then
            if command -v update-alternatives > /dev/null 2>&1; then
                update-alternatives --install "/usr/bin/${tool}" "${tool}" "${tool_bin}" "${priority}" 2> /dev/null || true
                update-alternatives --set "${tool}" "${tool_bin}" 2> /dev/null || true
            else
                rm -f "/usr/bin/${tool}"
                ln -sf "${tool_bin}" "/usr/bin/${tool}"
            fi
        fi
    done

    # Special case: ld.lld symlink
    local lld_bin=""
    if [[ -e "/usr/bin/lld-${LLVM_FULL_VERSION}" ]]; then
        lld_bin="/usr/bin/lld-${LLVM_FULL_VERSION}"
    elif [[ -e "/usr/bin/lld-${CLANG_VERSION}" ]]; then
        lld_bin="/usr/bin/lld-${CLANG_VERSION}"
    fi

    if [[ -n "${lld_bin}" ]]; then
        if command -v update-alternatives > /dev/null 2>&1; then
            update-alternatives --install /usr/bin/ld.lld ld.lld "${lld_bin}" "${priority}" 2> /dev/null || true
            update-alternatives --set ld.lld "${lld_bin}" 2> /dev/null || true
        else
            rm -f /usr/bin/ld.lld
            ln -sf "${lld_bin}" /usr/bin/ld.lld
        fi
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
