#!/bin/bash
#
# Prints kernel and OS information for debugging CI environments.
#

set -euo pipefail

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

print_section_header "Kernel Info"

info "uname -a:"
uname -a
print_separator

info "/proc/version:"
cat /proc/version
print_separator

info "/proc/version_signature:"
cat /proc/version_signature 2> /dev/null || info "(not found)"
print_separator

info "/etc/lsb-release:"
cat /etc/lsb-release 2> /dev/null || info "(not found)"
print_separator

info "/etc/os-release:"
cat /etc/os-release
print_separator
