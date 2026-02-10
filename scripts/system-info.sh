#!/bin/bash
#
# Prints system and tooling information for debugging CI environments.
# System information includes: kernel version, OS release, and BTF support.
# BPF information includes: bpftrace and bpftool versions and kernel features.
# Resource information includes: CPU, memory, swap, block devices, and mounts.
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
  --all        Show all information (default)
  --system     Show only system information (distro and kernel)
  --bpf        Show only BPF information (bpftrace, bpftool)
  --resources  Show only resource information (CPU, memory, disk)
  --tooling    Show only compiler/tooling information
  --help, -h   Show this help message

Examples:
  $0              # Show all info (default)
  $0 --system     # Show only system info (distro and kernel)
  $0 --bpf        # Show only BPF info (bpftrace, bpftool)
  $0 --resources  # Show only resource info (CPU, memory, disk)
  $0 --tooling    # Show only tooling info
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
        --bpf)
            MODE="bpf"
            shift
            ;;
        --resources)
            MODE="resources"
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
    print_cmd uname -a

    print_section_header "/proc/version" "-"
    print_cmd cat /proc/version

    print_section_header "/proc/version_signature" "-"
    if [[ -f /proc/version_signature ]]; then
        print_cmd cat /proc/version_signature
    else
        info "(not found)"
    fi

    print_section_header "/etc/lsb-release" "-"
    if [[ -f /etc/lsb-release ]]; then
        print_cmd cat /etc/lsb-release
    else
        info "(not found)"
    fi

    print_section_header "/etc/os-release" "-"
    print_cmd cat /etc/os-release

    readonly btf_vmlinux_path="/sys/kernel/btf/vmlinux"
    print_section_header "Kernel BTF support" "-"
    if [[ -f "${btf_vmlinux_path}" ]]; then
        info "BTF is available: ${btf_vmlinux_path} exists"
        print_cmd ls -lh "${btf_vmlinux_path}" || error "(ls failed)"
    else
        warn "BTF is not available: ${btf_vmlinux_path} not found"
    fi

    if [[ "${MODE}" == "all" ]]; then
        info
    fi
fi

# Show BPF info if mode is "all" or "bpf"
if [[ "${MODE}" == "all" || "${MODE}" == "bpf" ]]; then
    print_section_banner "BPF Info"

    print_section_header "bpftrace" "-"
    if command -v bpftrace > /dev/null 2>&1; then
        print_cmd bpftrace --version || error "(bpftrace version failed)"
        print_cmd bpftrace --info || error "(bpftrace info failed)"
    else
        info "(not found)"
    fi

    print_section_header "bpftool" "-"
    if command -v bpftool > /dev/null 2>&1 && bpftool version > /dev/null 2>&1; then
        print_cmd bpftool version || error "(bpftool version failed)"
        print_cmd bpftool feature || error "(bpftool feature failed)"
    else
        info "(not found or not available for current kernel)"
    fi

    if [[ "${MODE}" == "all" ]]; then
        info
    fi
fi

# Show resource info if mode is "all" or "resources"
if [[ "${MODE}" == "all" || "${MODE}" == "resources" ]]; then
    print_section_banner "Resource Info"

    print_section_header "CPU" "-"
    if [[ -f /proc/cpuinfo ]]; then
        # Show model name and count
        model=$(grep -m1 'model name' /proc/cpuinfo 2> /dev/null | cut -d: -f2 | sed 's/^ //' || true)
        if [[ -z "${model}" ]]; then
            # aarch64 doesn't have "model name", try "Hardware" field
            model=$(grep -m1 'Hardware' /proc/cpuinfo 2> /dev/null | cut -d: -f2 | sed 's/^ //' || true)
            if [[ -z "${model}" ]]; then
                model="$(uname -m)"
            fi
        fi
        cpu_count=$(grep -c '^processor' /proc/cpuinfo 2> /dev/null || echo "unknown")
        info "Model: ${model}"
        info "CPUs:  ${cpu_count}"
    else
        info "(cpuinfo not available)"
    fi

    print_section_header "Memory" "-"
    if command -v free > /dev/null 2>&1; then
        print_cmd free -h
    elif [[ -f /proc/meminfo ]]; then
        print_cmd grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached)' /proc/meminfo
    else
        info "(memory info not available)"
    fi

    print_section_header "Swap" "-"
    if command -v swapon > /dev/null 2>&1; then
        print_cmd swapon --show || info "No swap configured"
    elif [[ -f /proc/swaps ]]; then
        print_cmd cat /proc/swaps
    else
        info "(swap info not available)"
    fi

    print_section_header "Block Devices" "-"
    if command -v lsblk > /dev/null 2>&1; then
        print_cmd lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT || print_cmd lsblk || info "(lsblk failed)"
    else
        info "(lsblk not available)"
    fi

    print_section_header "Disk Usage" "-"
    if command -v df > /dev/null 2>&1; then
        print_cmd df -h -x tmpfs -x devtmpfs -x squashfs || print_cmd df -h || info "(df failed)"
    else
        info "(df not available)"
    fi

    print_section_header "Mount Points" "-"
    if command -v findmnt > /dev/null 2>&1; then
        print_cmd findmnt -t ext4,xfs,btrfs,vfat,overlay,nfs,cifs --notruncate || print_cmd findmnt --real || info "(findmnt failed)"
    elif [[ -f /proc/mounts ]]; then
        print_cmd grep -vE '^(proc|sysfs|devpts|tmpfs|cgroup|securityfs|debugfs|tracefs|mqueue|hugetlbfs|bpf|pstore)' /proc/mounts
    else
        info "(mount info not available)"
    fi

    if [[ "${MODE}" == "all" ]]; then
        info
    fi
fi

# Show tooling info if mode is "all" or "tooling"
if [[ "${MODE}" == "all" || "${MODE}" == "tooling" ]]; then
    print_section_banner "Compiler Info"

    print_section_header "gcc version" "-"
    print_cmd gcc --version || info "(not found)"

    print_section_header "clang version" "-"
    print_cmd clang --version || info "(not found)"

    print_section_header "golang version" "-"
    print_cmd go version || info "(not found)"
fi
