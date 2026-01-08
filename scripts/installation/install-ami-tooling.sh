#!/bin/sh
#
# Install AWS CLI, GitHub CLI, and GitHub Actions Runner on AMI instances
#
# This script detects the platform and installs required tooling for
# running GitHub Actions runners on AWS AMI instances.
#

set -eu

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - versions of tools to install
#
# IMPORTANT: When updating ACTIONS_RUNNER_VERSION, you must also update the
# corresponding checksum files in scripts/installation/checksums/:
#   - actions-runner-linux-x64-{VERSION}.sha256
#   - actions-runner-linux-arm64-{VERSION}.sha256
readonly ACTIONS_RUNNER_VERSION="2.330.0"

# Path to AWS CLI GPG public key for signature verification
# Key fingerprint: FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C
# Source: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
readonly AWS_CLI_GPG_KEY_FILE="${SCRIPT_DIR}/keys/aws-cli-public-key.asc"

# Architecture variables (set by detect_platform_and_architecture function)
ARCH_AWSCLI=""
ARCH_ACTIONS_RUNNER=""

# Platform and architecture variables (set by detect_platform_and_architecture function)
PLATFORM=""
ARCHITECTURE=""

# Detects platform and architecture for all installation needs
# Sets global variables: PLATFORM, ARCHITECTURE, ARCH_AWSCLI, ARCH_ACTIONS_RUNNER
detect_platform_and_architecture() {
    # Detect platform from os-release
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        PLATFORM="${ID}"
    else
        die "Cannot detect platform: /etc/os-release not found" 1
    fi

    # Detect architecture using uname (portable across all platforms)
    system_arch="$(uname -m)"

    info "Detected platform: ${PLATFORM}, architecture: ${system_arch}"

    # Map system architecture to:
    # 1. ARCHITECTURE - for apt/yum repository configuration
    # 2. ARCH_AWSCLI - for AWS CLI downloads
    # 3. ARCH_ACTIONS_RUNNER - for GitHub Actions Runner downloads
    case "${system_arch}" in
        x86_64)
            ARCHITECTURE="amd64"
            ARCH_AWSCLI="x86_64"
            ARCH_ACTIONS_RUNNER="x64"
            ;;
        aarch64)
            ARCHITECTURE="arm64"
            ARCH_AWSCLI="aarch64"
            ARCH_ACTIONS_RUNNER="arm64"
            ;;
        *)
            die "Unsupported architecture: ${system_arch}. Supported: x86_64, aarch64" 1
            ;;
    esac

    info "Repository architecture: ${ARCHITECTURE}"
    info "AWS CLI architecture: ${ARCH_AWSCLI}"
    info "GitHub Actions Runner architecture: ${ARCH_ACTIONS_RUNNER}"

    # Make variables readonly after setting
    readonly PLATFORM
    readonly ARCHITECTURE
    readonly ARCH_AWSCLI
    readonly ARCH_ACTIONS_RUNNER
}

# Installs AWS CLI package for the detected architecture
install_aws_cli_package() {
    # Remove local temporary files and directories
    rm -rf aws
    rm -f awscliv2.zip awscliv2.zip.sig

    aws_cli_url="https://awscli.amazonaws.com/awscli-exe-linux-${ARCH_AWSCLI}.zip"

    # Download AWS CLI archive
    info "Downloading AWS CLI archive..."
    if ! curl -fsSL "${aws_cli_url}" -o "awscliv2.zip"; then
        error "Failed to download AWS CLI archive"
        return 1
    fi

    # Download AWS CLI signature
    info "Downloading AWS CLI signature..."
    if ! curl -fsSL "${aws_cli_url}.sig" -o "awscliv2.zip.sig"; then
        error "Failed to download AWS CLI signature file"
        rm -f awscliv2.zip
        return 1
    fi

    # Verify the signature before installation
    if ! verify_gpg_signature "awscliv2.zip" "awscliv2.zip.sig" "${AWS_CLI_GPG_KEY_FILE}" "AWS CLI"; then
        error "Aborting AWS CLI installation due to signature verification failure"
        rm -f awscliv2.zip awscliv2.zip.sig
        return 1
    fi

    # Signature verified, proceed with installation
    info "Installing AWS CLI..."
    unzip -q awscliv2.zip
    sudo ./aws/install --update

    # Cleanup temporary files
    rm -f awscliv2.zip awscliv2.zip.sig
    rm -rf aws
}

# Installs required packages based on detected platform
# Expects PLATFORM and ARCHITECTURE environment variables to be set
install_packages() {
    mutualPackagesNeeded='jq gh curl tar unzip gnupg'

    case "${PLATFORM}" in
        debian | ubuntu)
            info "About to install ${mutualPackagesNeeded} with apt-get"
            command -v curl > /dev/null || sudo apt install curl -y
            curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
                | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
            sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
            echo "deb [arch=${ARCHITECTURE} signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
                | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
            sudo apt-get update
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo apt-get install ${mutualPackagesNeeded} -y
            ;;
        amzn)
            info "About to install ${mutualPackagesNeeded} with yum"
            sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo yum install ${mutualPackagesNeeded} -y
            sudo yum install libicu -y
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo yum update ${mutualPackagesNeeded} -y
            ;;
        centos | rhel)
            info "About to install ${mutualPackagesNeeded} with yum"
            sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo yum install ${mutualPackagesNeeded} -y
            sudo yum install libicu -y
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo yum update ${mutualPackagesNeeded} -y
            export GITHUB_ACTIONS_RUNNER_TLS_NO_VERIFY=1 # Until we find a solution for certificate below (At the moment download cert and put in few locations didnt solve the issue)
            # sudo openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > githubcert.pem
            # git config --global http.https://github.com/.sslCAInfo githubcert.pem
            ;;
        ol | fedora)
            info "About to install ${mutualPackagesNeeded} with dnf"
            sudo dnf install 'dnf-command(config-manager)' -y
            sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo dnf install ${mutualPackagesNeeded} -y
            sudo dnf install libicu -y
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo dnf update ${mutualPackagesNeeded} -y
            ;;
        sles)
            info "About to install ${mutualPackagesNeeded} with zypper"
            sudo zypper addrepo https://cli.github.com/packages/rpm/gh-cli.repo
            sudo zypper --gpg-auto-import-keys ref
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo zypper install -y ${mutualPackagesNeeded}
            sudo zypper --gpg-auto-import-keys ref
            # shellcheck disable=SC2086  # Word splitting intentional for package list
            sudo zypper update -y ${mutualPackagesNeeded}
            ;;
        *)
            die \
                "Error installing packages. Package manager not found. You must manually install: ${mutualPackagesNeeded}" \
                1
            ;;
    esac
}

# Downloads GitHub Actions runner for the detected architecture
download_actions_runner() {
    tarball_name="actions-runner-linux-${ARCH_ACTIONS_RUNNER}-${ACTIONS_RUNNER_VERSION}.tar.gz"
    checksum_file="${SCRIPT_DIR}/checksums/actions-runner-linux-${ARCH_ACTIONS_RUNNER}-${ACTIONS_RUNNER_VERSION}.sha256"
    runner_base_url="https://github.com/actions/runner/releases/download/v${ACTIONS_RUNNER_VERSION}"

    # Check that the pinned checksum file exists
    if [ ! -f "${checksum_file}" ]; then
        error "Checksum file not found: ${checksum_file}"
        error "When updating ACTIONS_RUNNER_VERSION, you must also add the corresponding checksum file."
        error "Download from: ${runner_base_url}/${tarball_name}.sha256"
        return 1
    fi

    # Remove local temporary directory and files if they exist
    rm -rf actions-runner
    rm -f "${tarball_name}"
    mkdir -p actions-runner

    # Download runner tarball
    info "Downloading GitHub Actions Runner tarball..."
    if ! curl -fsSL -o "${tarball_name}" "${runner_base_url}/${tarball_name}"; then
        error "Failed to download GitHub Actions Runner tarball"
        return 1
    fi

    # Verify the checksum before extraction using pinned checksum file
    if ! verify_sha256_checksum "${tarball_name}" "${checksum_file}" "GitHub Actions Runner"; then
        error "Aborting GitHub Actions Runner installation due to checksum verification failure"
        rm -f "${tarball_name}"
        return 1
    fi

    # Checksum verified, proceed with extraction
    info "Extracting GitHub Actions Runner..."
    tar \
        -xzf "${tarball_name}" \
        -C actions-runner

    # Remove destination directory and install new version
    info "Installing GitHub Actions Runner to /actions-runner"
    sudo rm -rf /actions-runner
    sudo cp -r actions-runner /actions-runner

    # Cleanup all temporary files and downloads
    rm -f "${tarball_name}"
    rm -rf actions-runner
    info "Downloaded and installed actions-runner v${ACTIONS_RUNNER_VERSION}"
}

# Verifies that all required tools were installed successfully
# Note: curl, tar, unzip are already verified by require_cmds earlier
# Returns:
#   0 if all tools are present, 1 if any are missing
verify_installation() {
    info "Verifying installation..."

    missing_tools=""
    # Only check tools not yet verified: aws (from AWS CLI), jq/gh (from install_packages)
    required_commands="aws jq gh"

    # Check each required command
    for cmd in ${required_commands}; do
        if ! command -v "${cmd}" > /dev/null 2>&1; then
            missing_tools="${missing_tools} ${cmd}"
            error "Missing: ${cmd}"
        else
            info "Found: ${cmd}"
        fi
    done

    # Check if actions-runner is properly installed
    if [ ! -d "/actions-runner" ]; then
        missing_tools="${missing_tools} actions-runner"
        error "Missing: /actions-runner directory"
    elif [ ! -f "/actions-runner/run.sh" ] || [ ! -f "/actions-runner/config.sh" ]; then
        missing_tools="${missing_tools} actions-runner"
        error "Missing: /actions-runner installation incomplete (missing run.sh or config.sh)"
    elif [ ! -d "/actions-runner/bin" ]; then
        missing_tools="${missing_tools} actions-runner"
        error "Missing: /actions-runner/bin directory"
    else
        info "Found: /actions-runner with run.sh, config.sh, and bin/"
    fi

    # Report results
    if [ -n "${missing_tools}" ]; then
        error "Installation incomplete. Missing tools:${missing_tools}"
        return 1
    else
        info "All tools installed successfully!"
        return 0
    fi
}

# Main function
main() {
    # Detect platform and architecture first
    detect_platform_and_architecture

    # Check for essential commands (curl, tar, unzip will be installed by install_packages)
    info "Checking for essential commands..."
    require_cmds uname sudo

    info "Install prerequisites packages"
    install_packages

    # Verify tools needed for downloads are now available
    info "Verifying download tools..."
    require_cmds curl tar unzip gpg

    info "Install AWS cli package"
    install_aws_cli_package

    info "Download GitHub actions-runner"
    download_actions_runner

    if ! verify_installation; then
        die "Installation failed"
    fi
}

# Main execution
main "$@"
