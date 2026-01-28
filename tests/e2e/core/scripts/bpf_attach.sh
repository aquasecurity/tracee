#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

info() {
    echo -n "INFO: "
    echo "$@"
}

# SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# disable_unattended_upgrades="${SCRIPT_DIR}/../../../scripts/disable-unattended-upgrades.sh"

# Parse command line arguments
INSTALL=false
RUN=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --install)
            INSTALL=true
            RUN=false
            shift
            ;;
        --run)
            RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--install] [--run]"
            exit 1
            ;;
    esac
done

# Install phase: install bpftrace if needed
if [[ "$INSTALL" == "true" ]]; then
    if command -v bpftrace > /dev/null 2>&1; then
        info "bpftrace already available"
        exit 0
    fi

    info "installing bpftrace..."

    # Detect distribution and install bpftrace
    # TODO: install bpftrace in the AMIs and remove this logic
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID}" in
            ubuntu | debian)
                # Check if this is an EOL Ubuntu release
                if [[ "${ID}" == "ubuntu" ]] \
                    && [[ "${VERSION_CODENAME}" == "mantic" || "${VERSION_CODENAME}" == "lunar" ]]; then
                    #
                    info "detected EOL Ubuntu ${VERSION_CODENAME}, switching to old-releases repository..."
                    # Architecture-specific repository replacement
                    if [[ "$(uname -m)" == "aarch64" ]] || [[ "$(uname -m)" == "arm64" ]]; then
                        # For aarch64/arm64: ports repositories → old-releases ubuntu (not ubuntu-ports)
                        sed -i 's|http://.*ports\.ubuntu\.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list
                        sed -i 's|http://.*\.ec2\.ports\.ubuntu\.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list
                        sed -i 's|http://.*ec2\.ports\.ubuntu\.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list
                    else
                        # For x86_64: archive repositories → old-releases ubuntu
                        sed -i 's|http://.*archive\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list
                        sed -i 's|http://security\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list
                    fi
                fi

                apt-get update > /dev/null 2>&1 || exit_err "failed to update apt repositories"
                apt-get install -y bpftrace > /dev/null 2>&1 || exit_err "failed to install bpftrace"

                ;;
            rhel | centos | fedora | almalinux | rocky)
                if command -v dnf > /dev/null 2>&1; then
                    # Try with GPG check first, then without if it fails
                    dnf install -y bpftrace > /dev/null 2>&1 || {
                        info "dnf install failed, trying with --nogpgcheck..."
                        dnf install -y --nogpgcheck bpftrace > /dev/null 2>&1 || exit_err "failed to install bpftrace via dnf (tried with and without GPG check)"
                    }
                elif command -v yum > /dev/null 2>&1; then
                    # Try with GPG check first, then without if it fails
                    yum install -y bpftrace > /dev/null 2>&1 || {
                        info "yum install failed, trying with --nogpgcheck..."
                        yum install -y --nogpgcheck bpftrace > /dev/null 2>&1 || exit_err "failed to install bpftrace via yum (tried with and without GPG check)"
                    }
                else
                    exit_err "no package manager found for RHEL/CentOS/AlmaLinux/Rocky"
                fi
                ;;

            *)
                exit_err "unsupported distribution: $ID (supported: ubuntu, debian, rhel, centos, fedora, almalinux, rocky)"
                ;;
        esac
    else
        exit_err "cannot detect distribution (no /etc/os-release)"
    fi

    # Verify installation
    if ! command -v bpftrace > /dev/null 2>&1; then
        exit_err "bpftrace installation failed"
    fi

    info "bpftrace installed successfully"
fi

# Run phase: execute bpftrace
if [[ "$RUN" == "true" ]]; then
    if ! command -v bpftrace > /dev/null 2>&1; then
        exit_err "bpftrace is required for the test but not available"
    fi

    sleep_time=${E2E_INST_TEST_SLEEP:-10}

    # Use bpftrace to attach a simple kprobe that should trigger BPF_ATTACH event
    # Run in background to ensure attachment happens, then let it run for the sleep time
    bpftrace -e 'kprobe:security_file_open { printf("BPF_ATTACH: security_file_open\n"); }' > /dev/null 2>&1 &
    bpftrace_pid=$!

    # Let it run for the configured time
    sleep "${sleep_time}"

    # Kill bpftrace
    kill -SIGINT "${bpftrace_pid}" 2> /dev/null || true
    wait "${bpftrace_pid}" 2> /dev/null || true
fi

exit 0
