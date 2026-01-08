#!/bin/bash
#
# Prints kernel and OS information for debugging CI environments.
#

set -euo pipefail

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

require_cmds cat ls stdbuf uname

# Disable output buffering for stdout
# This ensures all output appears immediately without buffering delays
exec 1> >(stdbuf -o 0 -e 0 cat)

print_section_header "System Info"

info "uname -a:"
uname -a
info

info "/proc/version:"
cat /proc/version
info

info "/proc/version_signature:"
if [[ -f /proc/version_signature ]]; then
    cat /proc/version_signature
else
    info "(not found)"
fi
info

info "/etc/lsb-release:"
if [[ -f /etc/lsb-release ]]; then
    cat /etc/lsb-release
else
    info "(not found)"
fi
info

info "/etc/os-release:"
cat /etc/os-release
info

readonly btf_vmlinux_path="/sys/kernel/btf/vmlinux"
info "Kernel BTF support:"
if [[ -f "${btf_vmlinux_path}" ]]; then
    info "BTF is available: ${btf_vmlinux_path} exists"
    ls -lh "${btf_vmlinux_path}" 2> /dev/null || true
else
    warn "BTF is not available: ${btf_vmlinux_path} not found"
fi
print_separator

print_section_header "Compiler Info"

info "gcc version:"
gcc --version 2> /dev/null || info "(not found)"
info

info "clang version:"
clang --version 2> /dev/null || info "(not found)"
info

info "golang version:"
go version 2> /dev/null || info "(not found)"
print_separator
