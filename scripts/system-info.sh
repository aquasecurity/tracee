#!/bin/bash
#
# Prints system and tooling information for debugging CI environments.
# System information includes: kernel version, OS release, and BTF support.
# Tooling information includes: gcc, clang, and golang compiler versions.
#

set -euo pipefail

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

require_cmds cat ls uname

# Shows help message and exits
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Prints kernel and OS information for debugging CI environments.

Options:
  --all       Show all system and tooling information (default)
  --system    Show only system information (distro and kernel)
  --tooling   Show only compiler/tooling information
  --help, -h  Show this help message

Examples:
  $0           # Show all system and tooling info (default)
  $0 --all     # Show all system and tooling info
  $0 --system  # Show only system info (distro and kernel)
  $0 --tooling # Show only tooling info
EOF
}

# Parse command line arguments
# Default mode is "all" (show everything)
MODE="all"
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            MODE="all"
            shift
            ;;
        --system)
            MODE="system"
            shift
            ;;
        --tooling)
            MODE="tooling"
            shift
            ;;
        --help | -h)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            error "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Redirect stderr to stdout to merge both streams and prevent interleaving
exec 2>&1

# Show system info if mode is "all" or "system"
if [[ "${MODE}" == "all" || "${MODE}" == "system" ]]; then
    print_section_banner "System Info"

    print_section_header "uname -a" "-"
    uname -a

    print_section_header "/proc/version" "-"
    cat /proc/version

    print_section_header "/proc/version_signature" "-"
    if [[ -f /proc/version_signature ]]; then
        cat /proc/version_signature
    else
        info "(not found)"
    fi

    print_section_header "/etc/lsb-release" "-"
    if [[ -f /etc/lsb-release ]]; then
        cat /etc/lsb-release
    else
        info "(not found)"
    fi

    print_section_header "/etc/os-release" "-"
    cat /etc/os-release

    readonly btf_vmlinux_path="/sys/kernel/btf/vmlinux"
    print_section_header "Kernel BTF support" "-"
    if [[ -f "${btf_vmlinux_path}" ]]; then
        info "BTF is available: ${btf_vmlinux_path} exists"
        ls -lh "${btf_vmlinux_path}" 2> /dev/null || true
    else
        warn "BTF is not available: ${btf_vmlinux_path} not found"
    fi

    # Add blank line only if we're printing tooling info next (sequential print)
    if [[ "${MODE}" == "all" ]]; then
        info
    fi
fi

# Show tooling info if mode is "all" or "tooling"
if [[ "${MODE}" == "all" || "${MODE}" == "tooling" ]]; then
    print_section_banner "Compiler Info"

    print_section_header "gcc version" "-"
    gcc --version 2> /dev/null || info "(not found)"

    print_section_header "clang version" "-"
    clang --version 2> /dev/null || info "(not found)"

    print_section_header "golang version" "-"
    go version 2> /dev/null || info "(not found)"
fi
