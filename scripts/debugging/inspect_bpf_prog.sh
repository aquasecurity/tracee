#!/bin/bash
# Inspect and measure eBPF programs in BPF object files.
# Supports measuring program sizes, dumping assembly, and comparing between files.
# Usage: ./inspect_bpf_prog.sh [options] [section_name]
# Use --help for detailed usage information.

set -euo pipefail

# Redirect stderr to stdout to make all printing linear and ordered
exec 2>&1

# Source lib.sh for consistent logging and utilities
__SCRIPT_DIR="${0%/*}"
__LIB_DIR="${__SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

__PROJECT_ROOT="${__SCRIPT_DIR}/../.."
BPF_OBJ="${BPF_OBJ:-${__PROJECT_ROOT}/dist/tracee.bpf.o}"
SECTION=""
DUMP=false
MEASURE=true
SHOW_SOURCE=false
SHOW_LINES=false
ALL_SECTIONS=false
EXPLICIT_MEASURE=false
EXPLICIT_DUMP=false
SHOW_SUMMARY=false
COMPARE_MODE=false
BASELINE_FILE=""
NEW_FILE=""
MATCH_SECTION=""

# Check for required tools
require_cmds llvm-objdump stat awk grep sort tail

# Helper function to validate hex string
# Returns 0 if valid hex, 1 otherwise
is_valid_hex() {
    local hex_str="$1"
    [[ "${hex_str}" =~ ^[0-9a-fA-F]+$ ]]
}

# Helper function to get file size (cross-platform)
# Arguments:
#   $1 - File path
# Returns: File size in bytes (or "0" if file not found)
get_file_size() {
    local file_path="$1"
    stat -c%s "${file_path}" 2> /dev/null || stat -f%z "${file_path}" 2> /dev/null || echo "0"
}

# Helper function to format bytes with human-readable suffix
# Arguments:
#   $1 - Size in bytes
# Returns: Formatted string (e.g., "1024 bytes" or "1.0KiB")
format_bytes() {
    local bytes="$1"
    numfmt --to=iec-i --suffix=B "${bytes}" 2> /dev/null || echo "${bytes} bytes"
}

# Helper function to calculate percentage change
# Arguments:
#   $1 - Baseline value
#   $2 - New value
# Returns: Percentage change as a string (e.g., "+136.9%" or "-5.2%")
calculate_percentage() {
    local baseline="$1"
    local new="$2"

    # If baseline is 0, can't calculate percentage
    if [[ "${baseline}" -eq 0 ]]; then
        echo ""
        return
    fi

    # Calculate percentage using awk for floating point precision
    local percent
    percent=$(awk -v baseline="${baseline}" -v new="${new}" 'BEGIN {
        diff = new - baseline
        percent = (diff / baseline) * 100
        if (percent >= 0) {
            printf "+%.1f%%", percent
        } else {
            printf "%.1f%%", percent
        }
    }')
    echo "${percent}"
}

# Helper function to format difference with sign
# Arguments:
#   $1 - Difference value
#   $2 - Label for the difference
#   $3 - Optional: "bytes" to format as bytes, otherwise plain number
#   $4 - Optional: Baseline value for percentage calculation
#   $5 - Optional: New value for percentage calculation
format_diff() {
    local diff_val="$1"
    local label="$2"
    local format_type="${3:-}"
    local baseline="${4:-}"
    local new="${5:-}"

    if [[ "${diff_val}" -eq 0 ]]; then
        return
    fi

    local sign=""
    if [[ "${diff_val}" -gt 0 ]]; then
        sign="+"
    fi

    # Calculate percentage if baseline and new values are provided
    local percent_str=""
    if [[ -n "${baseline}" ]] && [[ -n "${new}" ]] && [[ "${baseline}" -ne 0 ]]; then
        local percent
        percent=$(calculate_percentage "${baseline}" "${new}")
        if [[ -n "${percent}" ]]; then
            percent_str=", ${percent}"
        fi
    fi

    if [[ "${format_type}" = "bytes" ]]; then
        local abs_val="${diff_val#-}"
        info "${label}: ${sign}${diff_val} bytes ($(format_bytes "${abs_val}"))${percent_str}"
    else
        info "${label}: ${sign}${diff_val}${percent_str}"
    fi
}

# Helper function to count sections
# Arguments:
#   $1 - Sections string (newline-separated)
# Returns: Count of sections
count_sections() {
    local sections="$1"
    local count=0
    for _ in ${sections}; do
        count=$((count + 1))
    done
    echo "${count}"
}

# Associative array mapping BPF attach type names to their aliases
# Key: attach type name (ELF section name prefix, e.g., "kprobe", "xdp", "tcx/ingress")
# Value: space-separated list of aliases (including the canonical name itself)
# Note: Based on libbpf's section_defs[] array. Only entries explicitly marked as aliases
#       in libbpf source are treated as aliases here. All other entries are separate
#       definitions even if they share the same program type and attach type.
#       Use character class [.] to match literal dot (avoids awk escape warnings)
# Based on: libbpf source code (section_defs[] array)
declare -A BPF_PROGRAM_TYPE_ALIASES

# BPF_PROG_TYPE_KPROBE attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["kprobe"]="kprobe"
BPF_PROGRAM_TYPE_ALIASES["kretprobe"]="kretprobe"
BPF_PROGRAM_TYPE_ALIASES["ksyscall"]="ksyscall"
BPF_PROGRAM_TYPE_ALIASES["kretsyscall"]="kretsyscall"
BPF_PROGRAM_TYPE_ALIASES["uprobe"]="uprobe"
BPF_PROGRAM_TYPE_ALIASES["uprobe.s"]="uprobe[.]s"
BPF_PROGRAM_TYPE_ALIASES["uretprobe"]="uretprobe"
BPF_PROGRAM_TYPE_ALIASES["uretprobe.s"]="uretprobe[.]s"
BPF_PROGRAM_TYPE_ALIASES["usdt"]="usdt"
BPF_PROGRAM_TYPE_ALIASES["usdt.s"]="usdt[.]s"
BPF_PROGRAM_TYPE_ALIASES["kprobe.multi"]="kprobe[.]multi"
BPF_PROGRAM_TYPE_ALIASES["kretprobe.multi"]="kretprobe[.]multi"
BPF_PROGRAM_TYPE_ALIASES["kprobe.session"]="kprobe[.]session"
BPF_PROGRAM_TYPE_ALIASES["uprobe.multi"]="uprobe[.]multi"
BPF_PROGRAM_TYPE_ALIASES["uprobe.multi.s"]="uprobe[.]multi[.]s"
BPF_PROGRAM_TYPE_ALIASES["uretprobe.multi"]="uretprobe[.]multi"
BPF_PROGRAM_TYPE_ALIASES["uretprobe.multi.s"]="uretprobe[.]multi[.]s"
BPF_PROGRAM_TYPE_ALIASES["uprobe.session"]="uprobe[.]session"
BPF_PROGRAM_TYPE_ALIASES["uprobe.session.s"]="uprobe[.]session[.]s"

# BPF_PROG_TYPE_TRACEPOINT attach types
# tp is alias for tracepoint (same program type, attach type, and flags)
BPF_PROGRAM_TYPE_ALIASES["tracepoint"]="tracepoint tp"

# BPF_PROG_TYPE_RAW_TRACEPOINT attach types
# raw_tp is alias for raw_tracepoint (same program type, attach type, and flags)
BPF_PROGRAM_TYPE_ALIASES["raw_tracepoint"]="raw_tracepoint raw_tp"

# BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE attach types
# raw_tp.w is alias for raw_tracepoint.w (same program type, attach type, and flags)
BPF_PROGRAM_TYPE_ALIASES["raw_tracepoint.w"]="raw_tracepoint[.]w raw_tp[.]w"

# BPF_PROG_TYPE_XDP attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["xdp"]="xdp"
BPF_PROGRAM_TYPE_ALIASES["xdp.frags"]="xdp[.]frags"
BPF_PROGRAM_TYPE_ALIASES["xdp/cpumap"]="xdp/cpumap"
BPF_PROGRAM_TYPE_ALIASES["xdp.frags/cpumap"]="xdp[.]frags/cpumap"
BPF_PROGRAM_TYPE_ALIASES["xdp/devmap"]="xdp/devmap"
BPF_PROGRAM_TYPE_ALIASES["xdp.frags/devmap"]="xdp[.]frags/devmap"

# BPF_PROG_TYPE_TRACING attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["fentry"]="fentry"
BPF_PROGRAM_TYPE_ALIASES["fentry.s"]="fentry[.]s"
BPF_PROGRAM_TYPE_ALIASES["fexit"]="fexit"
BPF_PROGRAM_TYPE_ALIASES["fexit.s"]="fexit[.]s"
BPF_PROGRAM_TYPE_ALIASES["fmod_ret"]="fmod_ret"
BPF_PROGRAM_TYPE_ALIASES["fmod_ret.s"]="fmod_ret[.]s"
BPF_PROGRAM_TYPE_ALIASES["iter"]="iter"
BPF_PROGRAM_TYPE_ALIASES["iter.s"]="iter[.]s"
BPF_PROGRAM_TYPE_ALIASES["tp_btf"]="tp_btf"

# BPF_PROG_TYPE_LSM attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["lsm"]="lsm"
BPF_PROGRAM_TYPE_ALIASES["lsm.s"]="lsm[.]s"
BPF_PROGRAM_TYPE_ALIASES["lsm_cgroup"]="lsm_cgroup"

# BPF_PROG_TYPE_SCHED_CLS attach types
# tc/ingress and tc/egress are aliases for tcx/ingress and tcx/egress respectively
# (same program type, attach type, and flags)
BPF_PROGRAM_TYPE_ALIASES["tc"]="tc"
BPF_PROGRAM_TYPE_ALIASES["classifier"]="classifier"
BPF_PROGRAM_TYPE_ALIASES["tcx/ingress"]="tcx/ingress tc/ingress"
BPF_PROGRAM_TYPE_ALIASES["tcx/egress"]="tcx/egress tc/egress"
BPF_PROGRAM_TYPE_ALIASES["netkit/primary"]="netkit/primary"
BPF_PROGRAM_TYPE_ALIASES["netkit/peer"]="netkit/peer"

# BPF_PROG_TYPE_SCHED_ACT attach types
BPF_PROGRAM_TYPE_ALIASES["action"]="action"

# BPF_PROG_TYPE_CGROUP_SKB attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["cgroup/skb"]="cgroup/skb"
BPF_PROGRAM_TYPE_ALIASES["cgroup_skb/egress"]="cgroup_skb/egress"
BPF_PROGRAM_TYPE_ALIASES["cgroup_skb/ingress"]="cgroup_skb/ingress"

# BPF_PROG_TYPE_CGROUP_DEVICE attach types
BPF_PROGRAM_TYPE_ALIASES["cgroup/dev"]="cgroup/dev"

# BPF_PROG_TYPE_CGROUP_SOCKOPT attach types
BPF_PROGRAM_TYPE_ALIASES["cgroup/getsockopt"]="cgroup/getsockopt"
BPF_PROGRAM_TYPE_ALIASES["cgroup/setsockopt"]="cgroup/setsockopt"

# BPF_PROG_TYPE_CGROUP_SOCK_ADDR attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["cgroup/bind4"]="cgroup/bind4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/connect4"]="cgroup/connect4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getpeername4"]="cgroup/getpeername4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getsockname4"]="cgroup/getsockname4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/bind6"]="cgroup/bind6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/connect6"]="cgroup/connect6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getpeername6"]="cgroup/getpeername6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getsockname6"]="cgroup/getsockname6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/recvmsg4"]="cgroup/recvmsg4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sendmsg4"]="cgroup/sendmsg4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/recvmsg6"]="cgroup/recvmsg6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sendmsg6"]="cgroup/sendmsg6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/connect_unix"]="cgroup/connect_unix"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sendmsg_unix"]="cgroup/sendmsg_unix"
BPF_PROGRAM_TYPE_ALIASES["cgroup/recvmsg_unix"]="cgroup/recvmsg_unix"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getpeername_unix"]="cgroup/getpeername_unix"
BPF_PROGRAM_TYPE_ALIASES["cgroup/getsockname_unix"]="cgroup/getsockname_unix"

# BPF_PROG_TYPE_CGROUP_SOCK attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["cgroup/post_bind4"]="cgroup/post_bind4"
BPF_PROGRAM_TYPE_ALIASES["cgroup/post_bind6"]="cgroup/post_bind6"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sock_create"]="cgroup/sock_create"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sock"]="cgroup/sock"
BPF_PROGRAM_TYPE_ALIASES["cgroup/sock_release"]="cgroup/sock_release"

# BPF_PROG_TYPE_CGROUP_SYSCTL attach types
BPF_PROGRAM_TYPE_ALIASES["cgroup/sysctl"]="cgroup/sysctl"

# BPF_PROG_TYPE_EXT attach types
BPF_PROGRAM_TYPE_ALIASES["freplace"]="freplace"

# BPF_PROG_TYPE_FLOW_DISSECTOR attach types
BPF_PROGRAM_TYPE_ALIASES["flow_dissector"]="flow_dissector"

# BPF_PROG_TYPE_LIRC_MODE2 attach types
BPF_PROGRAM_TYPE_ALIASES["lirc_mode2"]="lirc_mode2"

# BPF_PROG_TYPE_LWT_* attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["lwt_in"]="lwt_in"
BPF_PROGRAM_TYPE_ALIASES["lwt_out"]="lwt_out"
BPF_PROGRAM_TYPE_ALIASES["lwt_seg6local"]="lwt_seg6local"
BPF_PROGRAM_TYPE_ALIASES["lwt_xmit"]="lwt_xmit"

# BPF_PROG_TYPE_NETFILTER attach types
BPF_PROGRAM_TYPE_ALIASES["netfilter"]="netfilter"

# BPF_PROG_TYPE_PERF_EVENT attach types
BPF_PROGRAM_TYPE_ALIASES["perf_event"]="perf_event"

# BPF_PROG_TYPE_SK_LOOKUP attach types
BPF_PROGRAM_TYPE_ALIASES["sk_lookup"]="sk_lookup"

# BPF_PROG_TYPE_SK_MSG attach types
BPF_PROGRAM_TYPE_ALIASES["sk_msg"]="sk_msg"

# BPF_PROG_TYPE_SK_REUSEPORT attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["sk_reuseport"]="sk_reuseport"
BPF_PROGRAM_TYPE_ALIASES["sk_reuseport/migrate"]="sk_reuseport/migrate"

# BPF_PROG_TYPE_SK_SKB attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["sk_skb"]="sk_skb"
BPF_PROGRAM_TYPE_ALIASES["sk_skb/stream_parser"]="sk_skb/stream_parser"
BPF_PROGRAM_TYPE_ALIASES["sk_skb/stream_verdict"]="sk_skb/stream_verdict"
BPF_PROGRAM_TYPE_ALIASES["sk_skb/verdict"]="sk_skb/verdict"

# BPF_PROG_TYPE_SOCKET_FILTER attach types
BPF_PROGRAM_TYPE_ALIASES["socket"]="socket"

# BPF_PROG_TYPE_SOCK_OPS attach types
BPF_PROGRAM_TYPE_ALIASES["sockops"]="sockops"

# BPF_PROG_TYPE_STRUCT_OPS attach types (all separate definitions)
BPF_PROGRAM_TYPE_ALIASES["struct_ops"]="struct_ops"
BPF_PROGRAM_TYPE_ALIASES["struct_ops.s"]="struct_ops[.]s"

# BPF_PROG_TYPE_SYSCALL attach types
BPF_PROGRAM_TYPE_ALIASES["syscall"]="syscall"

# Mapping of canonical attach type names to kernel C constants
# Format: "PROG_TYPE" if no separate attach type, or "PROG_TYPE:ATTACH_TYPE" if there is one
declare -A BPF_KERNEL_CONSTANTS

# Mapping of section names to their sec_def_flags
# Based on libbpf's section_defs[] array flags
declare -A BPF_SECTION_FLAGS
# BPF_PROG_TYPE_KPROBE (no separate attach type constants)
BPF_KERNEL_CONSTANTS["kprobe"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["kretprobe"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["ksyscall"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["kretsyscall"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["uprobe"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["uprobe.s"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["uretprobe"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["uretprobe.s"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["usdt"]="BPF_PROG_TYPE_KPROBE"
BPF_KERNEL_CONSTANTS["usdt.s"]="BPF_PROG_TYPE_KPROBE"
# BPF_PROG_TYPE_KPROBE with BPF_TRACE_KPROBE_MULTI attach type
BPF_KERNEL_CONSTANTS["kprobe.multi"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_KPROBE_MULTI"
BPF_KERNEL_CONSTANTS["kretprobe.multi"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_KPROBE_MULTI"
# BPF_PROG_TYPE_KPROBE with BPF_TRACE_KPROBE_SESSION attach type
BPF_KERNEL_CONSTANTS["kprobe.session"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_KPROBE_SESSION"
# BPF_PROG_TYPE_KPROBE with BPF_TRACE_UPROBE_MULTI attach type
BPF_KERNEL_CONSTANTS["uprobe.multi"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_MULTI"
BPF_KERNEL_CONSTANTS["uprobe.multi.s"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_MULTI"
BPF_KERNEL_CONSTANTS["uretprobe.multi"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_MULTI"
BPF_KERNEL_CONSTANTS["uretprobe.multi.s"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_MULTI"
# BPF_PROG_TYPE_KPROBE with BPF_TRACE_UPROBE_SESSION attach type
BPF_KERNEL_CONSTANTS["uprobe.session"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_SESSION"
BPF_KERNEL_CONSTANTS["uprobe.session.s"]="BPF_PROG_TYPE_KPROBE:BPF_TRACE_UPROBE_SESSION"
# BPF_PROG_TYPE_TRACEPOINT (no separate attach type)
BPF_KERNEL_CONSTANTS["tracepoint"]="BPF_PROG_TYPE_TRACEPOINT"
BPF_KERNEL_CONSTANTS["tp"]="BPF_PROG_TYPE_TRACEPOINT" # alias
# BPF_PROG_TYPE_RAW_TRACEPOINT (no separate attach type)
BPF_KERNEL_CONSTANTS["raw_tracepoint"]="BPF_PROG_TYPE_RAW_TRACEPOINT"
BPF_KERNEL_CONSTANTS["raw_tp"]="BPF_PROG_TYPE_RAW_TRACEPOINT" # alias
# BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE (no separate attach type)
BPF_KERNEL_CONSTANTS["raw_tracepoint.w"]="BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE"
BPF_KERNEL_CONSTANTS["raw_tp.w"]="BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE" # alias
# BPF_PROG_TYPE_XDP
BPF_KERNEL_CONSTANTS["xdp"]="BPF_PROG_TYPE_XDP:BPF_XDP"
BPF_KERNEL_CONSTANTS["xdp.frags"]="BPF_PROG_TYPE_XDP:BPF_XDP"
BPF_KERNEL_CONSTANTS["xdp/cpumap"]="BPF_PROG_TYPE_XDP:BPF_XDP_CPUMAP"
BPF_KERNEL_CONSTANTS["xdp.frags/cpumap"]="BPF_PROG_TYPE_XDP:BPF_XDP_CPUMAP"
BPF_KERNEL_CONSTANTS["xdp/devmap"]="BPF_PROG_TYPE_XDP:BPF_XDP_DEVMAP"
BPF_KERNEL_CONSTANTS["xdp.frags/devmap"]="BPF_PROG_TYPE_XDP:BPF_XDP_DEVMAP"
# BPF_PROG_TYPE_TRACING
BPF_KERNEL_CONSTANTS["fentry"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_FENTRY"
BPF_KERNEL_CONSTANTS["fentry.s"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_FENTRY"
BPF_KERNEL_CONSTANTS["fexit"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_FEXIT"
BPF_KERNEL_CONSTANTS["fexit.s"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_FEXIT"
BPF_KERNEL_CONSTANTS["fmod_ret"]="BPF_PROG_TYPE_TRACING:BPF_MODIFY_RETURN"
BPF_KERNEL_CONSTANTS["fmod_ret.s"]="BPF_PROG_TYPE_TRACING:BPF_MODIFY_RETURN"
BPF_KERNEL_CONSTANTS["iter"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_ITER"
BPF_KERNEL_CONSTANTS["iter.s"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_ITER"
BPF_KERNEL_CONSTANTS["tp_btf"]="BPF_PROG_TYPE_TRACING:BPF_TRACE_RAW_TP"
# BPF_PROG_TYPE_LSM
BPF_KERNEL_CONSTANTS["lsm"]="BPF_PROG_TYPE_LSM:BPF_LSM_MAC"
BPF_KERNEL_CONSTANTS["lsm.s"]="BPF_PROG_TYPE_LSM:BPF_LSM_MAC"
BPF_KERNEL_CONSTANTS["lsm_cgroup"]="BPF_PROG_TYPE_LSM:BPF_LSM_CGROUP"
# BPF_PROG_TYPE_SCHED_CLS (deprecated, no separate attach type for base tc/classifier)
BPF_KERNEL_CONSTANTS["tc"]="BPF_PROG_TYPE_SCHED_CLS"
BPF_KERNEL_CONSTANTS["classifier"]="BPF_PROG_TYPE_SCHED_CLS"
BPF_KERNEL_CONSTANTS["tcx/ingress"]="BPF_PROG_TYPE_SCHED_CLS:BPF_TCX_INGRESS"
BPF_KERNEL_CONSTANTS["tc/ingress"]="BPF_PROG_TYPE_SCHED_CLS:BPF_TCX_INGRESS"
BPF_KERNEL_CONSTANTS["tcx/egress"]="BPF_PROG_TYPE_SCHED_CLS:BPF_TCX_EGRESS"
BPF_KERNEL_CONSTANTS["tc/egress"]="BPF_PROG_TYPE_SCHED_CLS:BPF_TCX_EGRESS"
# BPF_PROG_TYPE_SCHED_ACT (no separate attach type)
BPF_KERNEL_CONSTANTS["action"]="BPF_PROG_TYPE_SCHED_ACT"
BPF_KERNEL_CONSTANTS["netkit/primary"]="BPF_PROG_TYPE_SCHED_CLS:BPF_NETKIT_PRIMARY"
BPF_KERNEL_CONSTANTS["netkit/peer"]="BPF_PROG_TYPE_SCHED_CLS:BPF_NETKIT_PEER"
# BPF_PROG_TYPE_CGROUP_SKB
BPF_KERNEL_CONSTANTS["cgroup/skb"]="BPF_PROG_TYPE_CGROUP_SKB"
BPF_KERNEL_CONSTANTS["cgroup_skb/egress"]="BPF_PROG_TYPE_CGROUP_SKB:BPF_CGROUP_INET_EGRESS"
BPF_KERNEL_CONSTANTS["cgroup_skb/ingress"]="BPF_PROG_TYPE_CGROUP_SKB:BPF_CGROUP_INET_INGRESS"
# BPF_PROG_TYPE_CGROUP_DEVICE
BPF_KERNEL_CONSTANTS["cgroup/dev"]="BPF_PROG_TYPE_CGROUP_DEVICE:BPF_CGROUP_DEVICE"
# BPF_PROG_TYPE_CGROUP_SOCKOPT
BPF_KERNEL_CONSTANTS["cgroup/getsockopt"]="BPF_PROG_TYPE_CGROUP_SOCKOPT:BPF_CGROUP_GETSOCKOPT"
BPF_KERNEL_CONSTANTS["cgroup/setsockopt"]="BPF_PROG_TYPE_CGROUP_SOCKOPT:BPF_CGROUP_SETSOCKOPT"
# BPF_PROG_TYPE_CGROUP_SOCK_ADDR
BPF_KERNEL_CONSTANTS["cgroup/bind4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET4_BIND"
BPF_KERNEL_CONSTANTS["cgroup/connect4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET4_CONNECT"
BPF_KERNEL_CONSTANTS["cgroup/getpeername4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET4_GETPEERNAME"
BPF_KERNEL_CONSTANTS["cgroup/getsockname4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET4_GETSOCKNAME"
BPF_KERNEL_CONSTANTS["cgroup/bind6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET6_BIND"
BPF_KERNEL_CONSTANTS["cgroup/connect6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET6_CONNECT"
BPF_KERNEL_CONSTANTS["cgroup/getpeername6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET6_GETPEERNAME"
BPF_KERNEL_CONSTANTS["cgroup/getsockname6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_INET6_GETSOCKNAME"
BPF_KERNEL_CONSTANTS["cgroup/recvmsg4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UDP4_RECVMSG"
BPF_KERNEL_CONSTANTS["cgroup/sendmsg4"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UDP4_SENDMSG"
BPF_KERNEL_CONSTANTS["cgroup/recvmsg6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UDP6_RECVMSG"
BPF_KERNEL_CONSTANTS["cgroup/sendmsg6"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UDP6_SENDMSG"
BPF_KERNEL_CONSTANTS["cgroup/connect_unix"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UNIX_CONNECT"
BPF_KERNEL_CONSTANTS["cgroup/sendmsg_unix"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UNIX_SENDMSG"
BPF_KERNEL_CONSTANTS["cgroup/recvmsg_unix"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UNIX_RECVMSG"
BPF_KERNEL_CONSTANTS["cgroup/getpeername_unix"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UNIX_GETPEERNAME"
BPF_KERNEL_CONSTANTS["cgroup/getsockname_unix"]="BPF_PROG_TYPE_CGROUP_SOCK_ADDR:BPF_CGROUP_UNIX_GETSOCKNAME"
# BPF_PROG_TYPE_CGROUP_SOCK
BPF_KERNEL_CONSTANTS["cgroup/post_bind4"]="BPF_PROG_TYPE_CGROUP_SOCK:BPF_CGROUP_INET4_POST_BIND"
BPF_KERNEL_CONSTANTS["cgroup/post_bind6"]="BPF_PROG_TYPE_CGROUP_SOCK:BPF_CGROUP_INET6_POST_BIND"
BPF_KERNEL_CONSTANTS["cgroup/sock_create"]="BPF_PROG_TYPE_CGROUP_SOCK:BPF_CGROUP_INET_SOCK_CREATE"
BPF_KERNEL_CONSTANTS["cgroup/sock"]="BPF_PROG_TYPE_CGROUP_SOCK:BPF_CGROUP_INET_SOCK_CREATE"
BPF_KERNEL_CONSTANTS["cgroup/sock_release"]="BPF_PROG_TYPE_CGROUP_SOCK:BPF_CGROUP_INET_SOCK_RELEASE"
# BPF_PROG_TYPE_CGROUP_SYSCTL
BPF_KERNEL_CONSTANTS["cgroup/sysctl"]="BPF_PROG_TYPE_CGROUP_SYSCTL:BPF_CGROUP_SYSCTL"
# BPF_PROG_TYPE_EXT (no separate attach type)
BPF_KERNEL_CONSTANTS["freplace"]="BPF_PROG_TYPE_EXT"
# BPF_PROG_TYPE_FLOW_DISSECTOR
BPF_KERNEL_CONSTANTS["flow_dissector"]="BPF_PROG_TYPE_FLOW_DISSECTOR:BPF_FLOW_DISSECTOR"
# BPF_PROG_TYPE_LIRC_MODE2
BPF_KERNEL_CONSTANTS["lirc_mode2"]="BPF_PROG_TYPE_LIRC_MODE2:BPF_LIRC_MODE2"
# BPF_PROG_TYPE_LWT_* (no separate attach types)
BPF_KERNEL_CONSTANTS["lwt_in"]="BPF_PROG_TYPE_LWT_IN"
BPF_KERNEL_CONSTANTS["lwt_out"]="BPF_PROG_TYPE_LWT_OUT"
BPF_KERNEL_CONSTANTS["lwt_seg6local"]="BPF_PROG_TYPE_LWT_SEG6LOCAL"
BPF_KERNEL_CONSTANTS["lwt_xmit"]="BPF_PROG_TYPE_LWT_XMIT"
# BPF_PROG_TYPE_NETFILTER
BPF_KERNEL_CONSTANTS["netfilter"]="BPF_PROG_TYPE_NETFILTER:BPF_NETFILTER"
# BPF_PROG_TYPE_PERF_EVENT (no separate attach type)
BPF_KERNEL_CONSTANTS["perf_event"]="BPF_PROG_TYPE_PERF_EVENT"
# BPF_PROG_TYPE_SK_LOOKUP
BPF_KERNEL_CONSTANTS["sk_lookup"]="BPF_PROG_TYPE_SK_LOOKUP:BPF_SK_LOOKUP"
# BPF_PROG_TYPE_SK_MSG
BPF_KERNEL_CONSTANTS["sk_msg"]="BPF_PROG_TYPE_SK_MSG:BPF_SK_MSG_VERDICT"
# BPF_PROG_TYPE_SK_REUSEPORT
BPF_KERNEL_CONSTANTS["sk_reuseport"]="BPF_PROG_TYPE_SK_REUSEPORT:BPF_SK_REUSEPORT_SELECT"
BPF_KERNEL_CONSTANTS["sk_reuseport/migrate"]="BPF_PROG_TYPE_SK_REUSEPORT:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
# BPF_PROG_TYPE_SK_SKB (no separate attach type for base)
BPF_KERNEL_CONSTANTS["sk_skb"]="BPF_PROG_TYPE_SK_SKB"
BPF_KERNEL_CONSTANTS["sk_skb/stream_parser"]="BPF_PROG_TYPE_SK_SKB:BPF_SK_SKB_STREAM_PARSER"
BPF_KERNEL_CONSTANTS["sk_skb/stream_verdict"]="BPF_PROG_TYPE_SK_SKB:BPF_SK_SKB_STREAM_VERDICT"
BPF_KERNEL_CONSTANTS["sk_skb/verdict"]="BPF_PROG_TYPE_SK_SKB:BPF_SK_SKB_VERDICT"
# BPF_PROG_TYPE_SOCKET_FILTER (no separate attach type)
BPF_KERNEL_CONSTANTS["socket"]="BPF_PROG_TYPE_SOCKET_FILTER"
# BPF_PROG_TYPE_SOCK_OPS
BPF_KERNEL_CONSTANTS["sockops"]="BPF_PROG_TYPE_SOCK_OPS:BPF_CGROUP_SOCK_OPS"
# BPF_PROG_TYPE_STRUCT_OPS (no separate attach type)
BPF_KERNEL_CONSTANTS["struct_ops"]="BPF_PROG_TYPE_STRUCT_OPS"
BPF_KERNEL_CONSTANTS["struct_ops.s"]="BPF_PROG_TYPE_STRUCT_OPS"
# BPF_PROG_TYPE_SYSCALL (no separate attach type)
BPF_KERNEL_CONSTANTS["syscall"]="BPF_PROG_TYPE_SYSCALL"

# Mapping of section names to their sec_def_flags (from libbpf section_defs[])
# Flags: SEC_NONE, SEC_ATTACHABLE, SEC_ATTACHABLE_OPT, SEC_SLEEPABLE, SEC_XDP_FRAGS, SEC_USDT, SEC_ATTACH_BTF
# Based on libbpf's section_defs[] array flags
BPF_SECTION_FLAGS["socket"]="SEC_NONE"
BPF_SECTION_FLAGS["sk_reuseport/migrate"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["sk_reuseport"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["kprobe"]="SEC_NONE"
BPF_SECTION_FLAGS["uprobe"]="SEC_NONE"
BPF_SECTION_FLAGS["uprobe.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["kretprobe"]="SEC_NONE"
BPF_SECTION_FLAGS["uretprobe"]="SEC_NONE"
BPF_SECTION_FLAGS["uretprobe.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["kprobe.multi"]="SEC_NONE"
BPF_SECTION_FLAGS["kretprobe.multi"]="SEC_NONE"
BPF_SECTION_FLAGS["kprobe.session"]="SEC_NONE"
BPF_SECTION_FLAGS["uprobe.multi"]="SEC_NONE"
BPF_SECTION_FLAGS["uretprobe.multi"]="SEC_NONE"
BPF_SECTION_FLAGS["uprobe.session"]="SEC_NONE"
BPF_SECTION_FLAGS["uprobe.multi.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["uretprobe.multi.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["uprobe.session.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["ksyscall"]="SEC_NONE"
BPF_SECTION_FLAGS["kretsyscall"]="SEC_NONE"
BPF_SECTION_FLAGS["usdt"]="SEC_USDT"
BPF_SECTION_FLAGS["usdt.s"]="SEC_USDT|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["tc/ingress"]="SEC_NONE"
BPF_SECTION_FLAGS["tc/egress"]="SEC_NONE"
BPF_SECTION_FLAGS["tcx/ingress"]="SEC_NONE"
BPF_SECTION_FLAGS["tcx/egress"]="SEC_NONE"
BPF_SECTION_FLAGS["tc"]="SEC_NONE"
BPF_SECTION_FLAGS["classifier"]="SEC_NONE"
BPF_SECTION_FLAGS["action"]="SEC_NONE"
BPF_SECTION_FLAGS["netkit/primary"]="SEC_NONE"
BPF_SECTION_FLAGS["netkit/peer"]="SEC_NONE"
BPF_SECTION_FLAGS["tracepoint"]="SEC_NONE"
BPF_SECTION_FLAGS["tp"]="SEC_NONE" # alias
BPF_SECTION_FLAGS["raw_tracepoint"]="SEC_NONE"
BPF_SECTION_FLAGS["raw_tp"]="SEC_NONE" # alias
BPF_SECTION_FLAGS["raw_tracepoint.w"]="SEC_NONE"
BPF_SECTION_FLAGS["raw_tp.w"]="SEC_NONE" # alias
BPF_SECTION_FLAGS["tp_btf"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["fentry"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["fmod_ret"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["fexit"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["fentry.s"]="SEC_ATTACH_BTF|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["fmod_ret.s"]="SEC_ATTACH_BTF|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["fexit.s"]="SEC_ATTACH_BTF|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["freplace"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["lsm"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["lsm.s"]="SEC_ATTACH_BTF|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["lsm_cgroup"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["iter"]="SEC_ATTACH_BTF"
BPF_SECTION_FLAGS["iter.s"]="SEC_ATTACH_BTF|SEC_SLEEPABLE"
BPF_SECTION_FLAGS["syscall"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["xdp.frags/devmap"]="SEC_XDP_FRAGS"
BPF_SECTION_FLAGS["xdp/devmap"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["xdp.frags/cpumap"]="SEC_XDP_FRAGS"
BPF_SECTION_FLAGS["xdp/cpumap"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["xdp.frags"]="SEC_XDP_FRAGS"
BPF_SECTION_FLAGS["xdp"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["perf_event"]="SEC_NONE"
BPF_SECTION_FLAGS["lwt_in"]="SEC_NONE"
BPF_SECTION_FLAGS["lwt_out"]="SEC_NONE"
BPF_SECTION_FLAGS["lwt_xmit"]="SEC_NONE"
BPF_SECTION_FLAGS["lwt_seg6local"]="SEC_NONE"
BPF_SECTION_FLAGS["sockops"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["sk_skb/stream_parser"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["sk_skb/stream_verdict"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["sk_skb/verdict"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["sk_skb"]="SEC_NONE"
BPF_SECTION_FLAGS["sk_msg"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["lirc_mode2"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["flow_dissector"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["cgroup_skb/ingress"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["cgroup_skb/egress"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["cgroup/skb"]="SEC_NONE"
BPF_SECTION_FLAGS["cgroup/sock_create"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sock_release"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sock"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["cgroup/post_bind4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/post_bind6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/bind4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/bind6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/connect4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/connect6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/connect_unix"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sendmsg4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sendmsg6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sendmsg_unix"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/recvmsg4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/recvmsg6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/recvmsg_unix"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getpeername4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getpeername6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getpeername_unix"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getsockname4"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getsockname6"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getsockname_unix"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/sysctl"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/getsockopt"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/setsockopt"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["cgroup/dev"]="SEC_ATTACHABLE_OPT"
BPF_SECTION_FLAGS["struct_ops"]="SEC_NONE"
BPF_SECTION_FLAGS["struct_ops.s"]="SEC_SLEEPABLE"
BPF_SECTION_FLAGS["sk_lookup"]="SEC_ATTACHABLE"
BPF_SECTION_FLAGS["netfilter"]="SEC_NONE"

# Build pipe-separated regex pattern from all aliases
BPF_PROGRAM_TYPES_PATTERN=""
for aliases in "${BPF_PROGRAM_TYPE_ALIASES[@]}"; do
    for alias in ${aliases}; do
        if [[ -z "${BPF_PROGRAM_TYPES_PATTERN}" ]]; then
            BPF_PROGRAM_TYPES_PATTERN="${alias}"
        else
            BPF_PROGRAM_TYPES_PATTERN="${BPF_PROGRAM_TYPES_PATTERN}|${alias}"
        fi
    done
done

# Helper function to check if a section matches the attach pattern considering aliases
# Arguments:
#   $1 - Section name
#   $2 - Match pattern (e.g., "xdp", "xdp/*", "xdp/cpumap")
# Returns: 0 if matches, 1 otherwise
section_matches_attach_pattern() {
    local section="$1"
    local pattern="$2"

    # Handle wildcard patterns like "xdp/*"
    if [[ "${pattern}" =~ ^([^/]+)/\*$ ]]; then
        local base_pattern="${BASH_REMATCH[1]}"
        # Find all canonical names that match the base pattern (base or starting with base/)
        local matching_canonicals=()
        for canonical in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
            # Check if canonical name matches base pattern
            if [[ "${canonical}" = "${base_pattern}" ]] || [[ "${canonical}" =~ ^"${base_pattern}"/ ]]; then
                matching_canonicals+=("${canonical}")
                continue
            fi
            # Check if any alias matches base pattern
            local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical}]}"
            for alias in ${aliases}; do
                local literal_alias="${alias//\[\.\]/.}"
                if [[ "${literal_alias}" = "${base_pattern}" ]]; then
                    matching_canonicals+=("${canonical}")
                    break
                fi
            done
        done

        # Check if section matches any of the matching canonical names or their aliases
        for canonical_name in "${matching_canonicals[@]}"; do
            local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
            for alias in ${aliases}; do
                local literal_alias="${alias//\[\.\]/.}"
                # Check if section starts with this alias followed by /
                if [[ "${section}" = "${literal_alias}" ]] || [[ "${section}" =~ ^"${literal_alias}"/ ]]; then
                    return 0
                fi
            done
        done
        return 1
    fi

    # Handle specific patterns like "xdp/cpumap"
    if [[ "${pattern}" =~ ^([^/]+)/(.+)$ ]]; then
        local base_pattern="${BASH_REMATCH[1]}"
        local suffix="${BASH_REMATCH[2]}"

        # Find canonical name for base pattern
        local canonical_name=""
        for canonical in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
            if [[ "${canonical}" = "${base_pattern}" ]]; then
                canonical_name="${canonical}"
                break
            fi
            # Check aliases
            local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical}]}"
            for alias in ${aliases}; do
                local literal_alias="${alias//\[\.\]/.}"
                if [[ "${literal_alias}" = "${base_pattern}" ]]; then
                    canonical_name="${canonical}"
                    break 2
                fi
            done
        done

        if [[ -n "${canonical_name}" ]]; then
            # Get all aliases for this canonical name
            local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
            for alias in ${aliases}; do
                local literal_alias="${alias//\[\.\]/.}"
                # Check if section matches alias/suffix
                if [[ "${section}" = "${literal_alias}/${suffix}" ]]; then
                    return 0
                fi
            done
        fi
        return 1
    fi

    # Handle simple patterns like "xdp" (matches all aliases)
    local canonical_name=""
    for canonical in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
        if [[ "${canonical}" = "${pattern}" ]]; then
            canonical_name="${canonical}"
            break
        fi
        # Check aliases
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical}]}"
        for alias in ${aliases}; do
            local literal_alias="${alias//\[\.\]/.}"
            if [[ "${literal_alias}" = "${pattern}" ]]; then
                canonical_name="${canonical}"
                break 2
            fi
        done
    done

    if [[ -n "${canonical_name}" ]]; then
        # Get all aliases for this canonical name
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        for alias in ${aliases}; do
            local literal_alias="${alias//\[\.\]/.}"
            # Check if section starts with this alias (exact match or followed by /)
            if [[ "${section}" = "${literal_alias}" ]] || [[ "${section}" =~ ^"${literal_alias}"/ ]]; then
                return 0
            fi
        done
    fi

    return 1
}

# Function to get all BPF program sections from object file
# Filters for BPF program section types (kprobe, tracepoint, uprobe, etc.)
get_all_sections() {
    local obj_file="${1:-${BPF_OBJ}}"
    local sections
    sections=$(llvm-objdump -h "${obj_file}" 2>&1 \
        | awk -v types="${BPF_PROGRAM_TYPES_PATTERN}" '$2 ~ "^(" types ")/" {print $2}' \
        | grep -v "^\.rel" \
        | sort -u)

    # Filter by section pattern if provided, considering aliases
    if [[ -n "${MATCH_SECTION}" ]]; then
        local filtered_sections=""
        for section in ${sections}; do
            if section_matches_attach_pattern "${section}" "${MATCH_SECTION}"; then
                if [[ -z "${filtered_sections}" ]]; then
                    filtered_sections="${section}"
                else
                    filtered_sections="${filtered_sections}"$'\n'"${section}"
                fi
            fi
        done
        sections="${filtered_sections}"
    fi

    echo "${sections}"
}

# Helper function to get canonical section name for a given section
# Arguments:
#   $1 - Section name (e.g., "kprobe/security_task_prctl", "raw_tp/sys_enter")
# Returns: Canonical section name (e.g., "kprobe", "raw_tracepoint") or empty if not found
get_canonical_section_name() {
    local section="$1"
    local best_match=""
    local best_canonical=""

    # Try to match the full section name or prefix against all canonical names and aliases
    for canonical_name in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        for alias in ${aliases}; do
            # Convert regex pattern [.] back to literal . for comparison
            local literal_alias="${alias//\[\.\]/.}"
            # Check if section starts with the alias followed by / or end of string
            if [[ "${section}" = "${literal_alias}" ]] || [[ "${section}" = "${literal_alias}"/* ]]; then
                # Prefer longer matches (more specific)
                if [[ ${#literal_alias} -gt ${#best_match} ]]; then
                    best_match="${literal_alias}"
                    best_canonical="${canonical_name}"
                fi
            fi
        done
    done

    if [[ -n "${best_canonical}" ]]; then
        echo "${best_canonical}"
        return
    fi

    # If no match found, return empty
    echo ""
}

# Function to measure program
# Sets global variables: MEASURED_SECTION_SIZE, MEASURED_INSN_COUNT, MEASURED_INSN_SLOTS
# Arguments:
#   $1 - Section name to measure
#   $2 - Object file path (optional, defaults to BPF_OBJ)
#   $3 - Quiet mode flag (optional, "true" to suppress output, defaults to "false")
measure_program() {
    local section="$1"
    local obj_file="${2:-${BPF_OBJ}}"
    local quiet="${3:-false}"

    if [[ "${quiet}" = false ]]; then
        print_separator "="
        info "Measurement of section: ${section}"
        print_separator "="
        info "Object file: ${obj_file}"

        # Get canonical section name and display program type, attach type, and flags
        local canonical_name
        canonical_name=$(get_canonical_section_name "${section}")
        if [[ -n "${canonical_name}" ]]; then
            local prog_type=""
            local attach_type=""
            local flags=""

            # Get program type and attach type from BPF_KERNEL_CONSTANTS
            if [[ -n "${BPF_KERNEL_CONSTANTS[${canonical_name}]:-}" ]]; then
                local constants="${BPF_KERNEL_CONSTANTS[${canonical_name}]}"
                if [[ "${constants}" =~ ^([^:]+):(.+)$ ]]; then
                    prog_type="${BASH_REMATCH[1]}"
                    attach_type="${BASH_REMATCH[2]}"
                else
                    prog_type="${constants}"
                    attach_type="(none)"
                fi
            fi

            # Get flags from BPF_SECTION_FLAGS
            flags="${BPF_SECTION_FLAGS[${canonical_name}]:-SEC_NONE}"

            # Display the information
            info "Program type: ${prog_type}"
            if [[ "${attach_type}" != "(none)" ]]; then
                info "Attach type:  ${attach_type}"
            fi
            info "Flags:        ${flags}"
        fi

        info ""
    fi

    # Count instructions (match lines with hex instruction bytes)
    # Allow llvm-objdump to fail (exit code 1 for empty sections without causing script exit
    INSN_COUNT=$(llvm-objdump -d -j "${section}" "${obj_file}" 2>&1 \
        | awk '/^[[:space:]]*[0-9a-f]+:[[:space:]]+[0-9a-f]{2}[[:space:]]+[0-9a-f]{2}/ {count++} END {print count+0}' || echo "0")

    # Get section size (from llvm-objdump -h, more reliable)
    # Format: "275 kprobe/security_task_prctl    00013010 0000000000000000 TEXT"
    # Use exact matching on field 2 to avoid partial matches (e.g., "test" matching "test_helper")
    # Compare field 2 exactly with the section name (awk handles multiple spaces as field separators correctly)
    SECTION_SIZE=$(llvm-objdump -h "${obj_file}" 2>&1 \
        | awk -v section="${section}" '$2 == section {print $3; exit}' || echo "")

    # Get last instruction offset (highest offset) - these are instruction indices, not byte offsets
    # Allow llvm-objdump to fail (exit code 1) for empty sections without causing script exit
    LAST_OFFSET_HEX=$(llvm-objdump -d -j "${section}" "${obj_file}" 2>&1 \
        | grep -E "^[[:space:]]*[0-9a-f]+:" \
        | tail -1 | awk -F: '{gsub(/^[[:space:]]+/, "", $1); print $1}' || echo "")

    # Calculate total instruction slots (offset + 1, since offsets are 0-indexed)
    # Note: ldimm64 instructions use 2 slots but show as 1 line in disassembly
    if [[ -n "${LAST_OFFSET_HEX}" ]] && is_valid_hex "${LAST_OFFSET_HEX}"; then
        LAST_OFFSET_DEC=$((0x${LAST_OFFSET_HEX}))
        TOTAL_SLOTS=$((LAST_OFFSET_DEC + 1))
    else
        TOTAL_SLOTS="N/A"
        LAST_OFFSET_DEC="N/A"
    fi

    # Store section size for summary calculation
    if [[ -n "${SECTION_SIZE}" ]] && is_valid_hex "${SECTION_SIZE}"; then
        MEASURED_SECTION_SIZE=$((0x${SECTION_SIZE}))
        MEASURED_INSN_SLOTS=$((MEASURED_SECTION_SIZE / 8))
    else
        MEASURED_SECTION_SIZE=0
        if [[ "${TOTAL_SLOTS}" != "N/A" ]]; then
            MEASURED_INSN_SLOTS=${TOTAL_SLOTS}
        else
            MEASURED_INSN_SLOTS=0
        fi
    fi

    # Store instruction count
    MEASURED_INSN_COUNT=${INSN_COUNT}

    # Check if section was not found
    if [[ -z "${SECTION_SIZE}" ]] && [[ "${INSN_COUNT}" -eq 0 ]] && [[ "${TOTAL_SLOTS}" = "N/A" ]]; then
        if [[ "${quiet}" = false ]]; then
            error "Section '${section}' not found in ${obj_file}"
        fi
        return 1
    fi

    if [[ "${quiet}" = false ]]; then
        info "Results:"
        if [[ -n "${SECTION_SIZE}" ]] && is_valid_hex "${SECTION_SIZE}"; then
            SECTION_SIZE_DEC=$((0x${SECTION_SIZE}))
            TOTAL_INSN_SLOTS=$((SECTION_SIZE_DEC / 8))
            info "  Section size: 0x${SECTION_SIZE} (${SECTION_SIZE_DEC} bytes)"
            info "  Instruction count: ${INSN_COUNT}"
            info "  Total instruction slots: ${TOTAL_INSN_SLOTS} (section_size / 8)"
            LDIMM64_COUNT=$((TOTAL_INSN_SLOTS - INSN_COUNT))
            if [[ "${LDIMM64_COUNT}" -gt 0 ]]; then
                info "  Estimated multi-slot instructions: ~${LDIMM64_COUNT}"
            fi
        else
            info "  Instruction count: ${INSN_COUNT}"
            if [[ "${TOTAL_SLOTS}" != "N/A" ]] && [[ "${LAST_OFFSET_DEC}" != "N/A" ]]; then
                info "  Total instruction slots (by offset): ${TOTAL_SLOTS}"
                info "  Last instruction slot: 0x${LAST_OFFSET_HEX} (decimal: ${LAST_OFFSET_DEC})"
            fi
        fi
    fi
}

# Function to dump assembly
dump_assembly() {
    local section="$1"

    print_section_banner "Disassembly of section: ${section}"
    info "Object file: ${BPF_OBJ}"
    if [[ "${SHOW_SOURCE}" = true ]] || [[ "${SHOW_LINES}" = true ]]; then
        info "Note: Source code and line numbers require debug info in the BPF object"
    fi
    info ""

    # Build llvm-objdump command with optional flags using array (safe from injection)
    local objdump_args=(-d)
    if [[ "${SHOW_SOURCE}" = true ]]; then
        objdump_args+=(--source)
    fi
    if [[ "${SHOW_LINES}" = true ]]; then
        objdump_args+=(--line-numbers)
    fi
    objdump_args+=(-j "${section}" "${BPF_OBJ}")

    llvm-objdump "${objdump_args[@]}" 2>&1
}

# Helper function to extract and normalize probe type from section name
# Maps aliases to their canonical names for consistent grouping
# Arguments:
#   $1 - Section name (e.g., "raw_tp/sys_enter", "cgroup/skb", or "kprobe/do_sys_open")
# Returns: Canonical attach type name (e.g., "raw_tracepoint", "cgroup_skb", "kprobe")
#          or original section name if no mapping found
extract_probe_type() {
    local section="$1"
    local probe_type=""

    # First, try to match the full section name or prefix (for cases like "cgroup/skb/egress")
    # Check all canonical names and their aliases, matching longest first
    local best_match=""
    local best_canonical=""
    for canonical_name in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        for alias in ${aliases}; do
            # Convert regex pattern [.] back to literal . for comparison
            local literal_alias="${alias//\[\.\]/.}"
            # Check if section starts with the alias followed by / or end of string
            if [[ "${section}" = "${literal_alias}" ]] || [[ "${section}" = "${literal_alias}"/* ]]; then
                # Prefer longer matches (more specific)
                if [[ ${#literal_alias} -gt ${#best_match} ]]; then
                    best_match="${literal_alias}"
                    best_canonical="${canonical_name}"
                fi
            fi
        done
    done

    if [[ -n "${best_canonical}" ]]; then
        echo "${best_canonical}"
        return
    fi

    # If no full match, extract prefix and try to match it
    if [[ "${section}" =~ ^([^/]+)/ ]]; then
        probe_type="${BASH_REMATCH[1]}"
    else
        # Section has no slash, use it as-is
        probe_type="${section}"
    fi

    # Check if the prefix matches any alias in our mapping
    for canonical_name in "${!BPF_PROGRAM_TYPE_ALIASES[@]}"; do
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        for alias in ${aliases}; do
            # Convert regex pattern [.] back to literal . for comparison
            local literal_alias="${alias//\[\.\]/.}"
            if [[ "${probe_type}" = "${literal_alias}" ]]; then
                echo "${canonical_name}"
                return
            fi
        done
    done

    # If no mapping found, return the original probe type
    echo "${probe_type}"
}

# Helper function to accumulate measurement totals
# Reads global variables: MEASURED_SECTION_SIZE, MEASURED_INSN_SLOTS, MEASURED_INSN_COUNT
# Updates global variables: TOTAL_PROGRAM_SIZE, TOTAL_INSN_SLOTS, TOTAL_INSN_COUNT
# Also tracks per-probe-type statistics if PROBE_TYPE_COUNTS and PROBE_TYPE_SIZES arrays exist
# Arguments:
#   $1 - Section name (optional, used for probe type tracking)
accumulate_totals() {
    local section="${1:-}"
    if [[ "${MEASURED_SECTION_SIZE}" -gt 0 ]]; then
        TOTAL_PROGRAM_SIZE=$((TOTAL_PROGRAM_SIZE + MEASURED_SECTION_SIZE))
        TOTAL_INSN_SLOTS=$((TOTAL_INSN_SLOTS + MEASURED_INSN_SLOTS))
        TOTAL_INSN_COUNT=$((TOTAL_INSN_COUNT + MEASURED_INSN_COUNT))

        # Track per-probe-type statistics if arrays are declared
        if [[ -n "${section}" ]] && [[ "${BASH_VERSION%%.*}" -ge 4 ]]; then
            # Check if arrays exist by trying to get their keys (will fail if not declared)
            if declare -p PROBE_TYPE_COUNTS &> /dev/null && declare -p PROBE_TYPE_SIZES &> /dev/null; then
                local probe_type
                probe_type=$(extract_probe_type "${section}")
                PROBE_TYPE_COUNTS["${probe_type}"]=$((${PROBE_TYPE_COUNTS["${probe_type}"]:-0} + 1))
                PROBE_TYPE_SIZES["${probe_type}"]=$((${PROBE_TYPE_SIZES["${probe_type}"]:-0} + MEASURED_SECTION_SIZE))
            fi
        fi
    fi
}

# Helper function to display summary
# Arguments:
#   $1 - Section count
#   $2 - Total program size
#   $3 - Total instruction count
#   $4 - Total instruction slots
#   $5 - Object file size (optional)
#   $6 - Show probe type breakdown (optional, "true" to show breakdown)
display_summary() {
    local section_count="$1"
    local total_size="$2"
    local total_insn_count="$3"
    local total_insn_slots="$4"
    local obj_file_size="${5:-}"
    local show_breakdown="${6:-false}"

    print_section_banner "Summary"
    info "Processed sections: ${section_count}"

    # Show probe type breakdown if requested and arrays exist
    if [[ "${show_breakdown}" = "true" ]] && [[ "${BASH_VERSION%%.*}" -ge 4 ]]; then
        # Check if arrays exist and have keys
        if declare -p PROBE_TYPE_COUNTS &> /dev/null && declare -p PROBE_TYPE_SIZES &> /dev/null; then
            local sorted_types
            sorted_types=$(printf '%s\n' "${!PROBE_TYPE_COUNTS[@]}" | sort)
            if [[ -n "${sorted_types}" ]]; then
                local breakdown_total=0
                for probe_type in ${sorted_types}; do
                    local count=${PROBE_TYPE_COUNTS["${probe_type}"]}
                    local size=${PROBE_TYPE_SIZES["${probe_type}"]}
                    breakdown_total=$((breakdown_total + size))
                    info " - ${probe_type}: ${count} ($(format_bytes "${size}"))"
                done
                # Verify breakdown total matches overall total (for debugging)
                if [[ "${breakdown_total}" -ne "${total_size}" ]]; then
                    error "Warning: Probe type breakdown total (${breakdown_total}) does not match total program size (${total_size})"
                fi
            fi
        fi
    fi

    if [[ "${total_size}" -gt 0 ]]; then
        info "Total program size: ${total_size} bytes ($(format_bytes "${total_size}"))"
        info "Total instruction count: ${total_insn_count}"
        info "Total instruction slots: ${total_insn_slots}"
    fi
    if [[ -n "${obj_file_size}" ]]; then
        info "Object file size: ${obj_file_size} bytes ($(format_bytes "${obj_file_size}"))"
    fi

    # Show informational notes only when not in --summary mode (to avoid repetition)
    if [[ "${show_breakdown}" = "false" ]]; then
        info ""
        info "Note: Each eBPF instruction is 8 bytes (64 bits)"
        info "Note: ldimm64 instructions span 2 instruction slots but show as 1 line in disassembly"
        info "Note: Instruction slots (0-indexed) represent the actual program size"
    fi

    print_separator "="
}

# Function to compare two BPF object files
compare_files() {
    local baseline_file="$1"
    local new_file="$2"

    if [[ ! -f "${baseline_file}" ]]; then
        die "Baseline file not found: ${baseline_file}"
    fi

    if [[ ! -f "${new_file}" ]]; then
        die "New file not found: ${new_file}"
    fi

    info "Comparing BPF object files:"
    info "  Baseline: ${baseline_file}"
    info "  New:      ${new_file}"
    info ""

    # Get all sections from both files
    BASELINE_SECTIONS=$(get_all_sections "${baseline_file}")
    NEW_SECTIONS=$(get_all_sections "${new_file}")

    # Combine and get unique sections
    ALL_SECTIONS=$(echo -e "${BASELINE_SECTIONS}\n${NEW_SECTIONS}" | sort -u)

    # Arrays to store measurements (associative arrays require bash 4+)
    if [[ "${BASH_VERSION%%.*}" -lt 4 ]]; then
        die "This script requires bash 4+ for comparison feature (current: ${BASH_VERSION})"
    fi

    declare -A baseline_sizes
    declare -A baseline_insn_counts
    declare -A baseline_insn_slots
    declare -A new_sizes
    declare -A new_insn_counts
    declare -A new_insn_slots

    # Measure baseline file
    info "Measuring baseline file..."
    for section in ${BASELINE_SECTIONS}; do
        measure_program "${section}" "${baseline_file}" true
        baseline_sizes["${section}"]=${MEASURED_SECTION_SIZE}
        baseline_insn_counts["${section}"]=${MEASURED_INSN_COUNT}
        baseline_insn_slots["${section}"]=${MEASURED_INSN_SLOTS}
    done

    # Measure new file
    info "Measuring new file..."
    for section in ${NEW_SECTIONS}; do
        measure_program "${section}" "${new_file}" true
        new_sizes["${section}"]=${MEASURED_SECTION_SIZE}
        new_insn_counts["${section}"]=${MEASURED_INSN_COUNT}
        new_insn_slots["${section}"]=${MEASURED_INSN_SLOTS}
    done

    info ""
    print_section_banner "Comparison Results"
    info ""

    # Find differences and calculate totals
    DIFF_COUNT=0
    TOTAL_SIZE_DIFF=0
    TOTAL_INSN_COUNT_DIFF=0
    TOTAL_INSN_SLOTS_DIFF=0
    TOTAL_BASELINE_SIZE=0
    TOTAL_BASELINE_INSN_COUNT=0
    TOTAL_BASELINE_INSN_SLOTS=0
    TOTAL_NEW_SIZE=0
    TOTAL_NEW_INSN_COUNT=0
    TOTAL_NEW_INSN_SLOTS=0

    for section in ${ALL_SECTIONS}; do
        baseline_size=${baseline_sizes["${section}"]:-0}
        baseline_insn_count=${baseline_insn_counts["${section}"]:-0}
        baseline_insn_slot=${baseline_insn_slots["${section}"]:-0}
        new_size=${new_sizes["${section}"]:-0}
        new_insn_count=${new_insn_counts["${section}"]:-0}
        new_insn_slot=${new_insn_slots["${section}"]:-0}

        # Check if section exists in both files
        if [[ "${baseline_size}" -eq 0 ]] && [[ "${new_size}" -eq 0 ]]; then
            continue
        fi

        # Accumulate totals for summary (include all sections, not just differences)
        TOTAL_BASELINE_SIZE=$((TOTAL_BASELINE_SIZE + baseline_size))
        TOTAL_BASELINE_INSN_COUNT=$((TOTAL_BASELINE_INSN_COUNT + baseline_insn_count))
        TOTAL_BASELINE_INSN_SLOTS=$((TOTAL_BASELINE_INSN_SLOTS + baseline_insn_slot))
        TOTAL_NEW_SIZE=$((TOTAL_NEW_SIZE + new_size))
        TOTAL_NEW_INSN_COUNT=$((TOTAL_NEW_INSN_COUNT + new_insn_count))
        TOTAL_NEW_INSN_SLOTS=$((TOTAL_NEW_INSN_SLOTS + new_insn_slot))

        # Check for differences
        size_diff=$((new_size - baseline_size))
        insn_count_diff=$((new_insn_count - baseline_insn_count))
        insn_slots_diff=$((new_insn_slot - baseline_insn_slot))

        if [[ "${size_diff}" -ne 0 ]] || [[ "${insn_count_diff}" -ne 0 ]] || [[ "${insn_slots_diff}" -ne 0 ]] || [[ "${baseline_size}" -eq 0 ]] || [[ "${new_size}" -eq 0 ]]; then
            DIFF_COUNT=$((DIFF_COUNT + 1))
            TOTAL_SIZE_DIFF=$((TOTAL_SIZE_DIFF + size_diff))
            TOTAL_INSN_COUNT_DIFF=$((TOTAL_INSN_COUNT_DIFF + insn_count_diff))
            TOTAL_INSN_SLOTS_DIFF=$((TOTAL_INSN_SLOTS_DIFF + insn_slots_diff))

            info "Section: ${section}"
            if [[ "${baseline_size}" -eq 0 ]]; then
                info "  Status: NEW (only in new file)"
            elif [[ "${new_size}" -eq 0 ]]; then
                info "  Status: REMOVED (only in baseline)"
            else
                info "  Status: MODIFIED"
            fi

            if [[ "${baseline_size}" -ne 0 ]] && [[ "${new_size}" -ne 0 ]]; then
                # Calculate percentages
                local size_percent
                size_percent=$(calculate_percentage "${baseline_size}" "${new_size}")
                local insn_count_percent
                insn_count_percent=$(calculate_percentage "${baseline_insn_count}" "${new_insn_count}")
                local insn_slots_percent
                insn_slots_percent=$(calculate_percentage "${baseline_insn_slot}" "${new_insn_slot}")

                info "  Size:            $(printf "%8d -> %8d (%+d bytes, %s)" "${baseline_size}" "${new_size}" "${size_diff}" "${size_percent}")"
                info "  Instruction cnt: $(printf "%8d -> %8d (%+d, %s)" "${baseline_insn_count}" "${new_insn_count}" "${insn_count_diff}" "${insn_count_percent}")"
                info "  Instruction slt: $(printf "%8d -> %8d (%+d, %s)" "${baseline_insn_slot}" "${new_insn_slot}" "${insn_slots_diff}" "${insn_slots_percent}")"
            elif [[ "${baseline_size}" -eq 0 ]]; then
                info "  Size:            $(printf "%8s -> %8d (new)" "N/A" "${new_size}")"
                info "  Instruction cnt: $(printf "%8s -> %8d (new)" "N/A" "${new_insn_count}")"
                info "  Instruction slt: $(printf "%8s -> %8d (new)" "N/A" "${new_insn_slot}")"
            else
                info "  Size:            $(printf "%8d -> %8s (removed)" "${baseline_size}" "N/A")"
                info "  Instruction cnt: $(printf "%8d -> %8s (removed)" "${baseline_insn_count}" "N/A")"
                info "  Instruction slt: $(printf "%8d -> %8s (removed)" "${baseline_insn_slot}" "N/A")"
            fi
            info ""
        fi
    done

    # Get object file sizes
    BASELINE_OBJ_SIZE=$(get_file_size "${baseline_file}")
    NEW_OBJ_SIZE=$(get_file_size "${new_file}")
    OBJ_SIZE_DIFF=$((NEW_OBJ_SIZE - BASELINE_OBJ_SIZE))

    # Display comparison summary
    print_section_banner "Summary"
    info "Programs with differences: ${DIFF_COUNT}"
    format_diff "${TOTAL_SIZE_DIFF}" "Total program size change" "bytes" "${TOTAL_BASELINE_SIZE}" "${TOTAL_NEW_SIZE}"
    format_diff "${TOTAL_INSN_COUNT_DIFF}" "Total instruction count change" "" "${TOTAL_BASELINE_INSN_COUNT}" "${TOTAL_NEW_INSN_COUNT}"
    format_diff "${TOTAL_INSN_SLOTS_DIFF}" "Total instruction slots change" "" "${TOTAL_BASELINE_INSN_SLOTS}" "${TOTAL_NEW_INSN_SLOTS}"
    if [[ -n "${MATCH_SECTION}" ]]; then
        format_diff "${OBJ_SIZE_DIFF}" "Object file size change (entire file)" "bytes" "${BASELINE_OBJ_SIZE}" "${NEW_OBJ_SIZE}"
    else
        format_diff "${OBJ_SIZE_DIFF}" "Object file size change" "bytes" "${BASELINE_OBJ_SIZE}" "${NEW_OBJ_SIZE}"
    fi
    if [[ "${DIFF_COUNT}" -eq 0 ]]; then
        info "No differences found - all programs are identical"
    fi
    print_separator "="
}

# Display usage information
usage() {
    echo "Usage: $0 [options] [section_name]"
    echo ""
    echo "Options:"
    echo "  -d, --dump           Dump assembly/disassembly of the program"
    echo "  -m, --measure        Measure program size (explicit, default behavior)"
    echo "  -a, --all            Both dump and measure"
    echo "  -s, --source         Include source code in dump (requires debug info)"
    echo "  -l, --lines          Include line numbers in dump (requires debug info)"
    echo "      --summary        Show only summary (requires measuring all sections)"
    echo "      --match-section  Filter sections by section name pattern (works with all modes)"
    echo "                       Usage: --match-section 'pattern' (e.g., 'xdp', 'xdp/*', 'xdp/cpumap')"
    echo "                       Matches section names and their aliases (e.g., 'xdp' matches 'xdp' and 'xdp.frags')"
    echo "      --list-sections  List all available BPF section types with program/attach types and flags"
    echo "  -c, --compare        Compare measurements between two BPF object files"
    echo "                       Usage: --compare baseline.bpf.o new.bpf.o"
    echo "                       Can be combined with --match-section to filter sections"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Default behavior:"
    echo "  No flags, no section: Measure all programs"
    echo "  Section specified:    Measure that single program"
    echo "  -d flag:              Dump (all programs or specified section)"
    echo ""
    echo "Environment variables:"
    echo "  BPF_OBJ               BPF object file path (default: dist/tracee.bpf.o)"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Measure all programs (default)"
    echo "  $0 --summary                                # Show only summary of all programs"
    echo "  $0 --match-section xdp                      # Measure all xdp sections (includes xdp.frags)"
    echo "  $0 --match-section 'xdp/*'                  # Measure all xdp/* variants (including aliases)"
    echo "  $0 --match-section xdp/cpumap               # Measure xdp/cpumap (includes xdp.frags/cpumap)"
    echo "  $0 --summary --match-section raw_tracepoint # Summary of all raw_tracepoint sections"
    echo "  $0 --list-sections                          # List all available section types"
    echo "  $0 -d                                       # Dump all programs"
    echo "  $0 -a                                       # Measure and dump all programs"
    echo "  $0 -d -s -l                                 # Dump all with source code and line numbers"
    echo "  $0 -c baseline.bpf.o new.bpf.o              # Compare two BPF object files"
    echo "  $0 --compare baseline.bpf.o new.bpf.o --match-section xdp  # Compare only xdp sections"
    echo "  $0 kprobe/security_task_prctl               # Measure specific section"
    echo "  $0 -d kprobe/security_task_prctl            # Dump specific section"
    echo "  $0 -a kprobe/security_task_prctl            # Measure and dump specific section"
}

# Function to list available match options
list_match_options() {
    echo "BPF program section types:"
    echo ""

    # First pass: calculate maximum widths for alignment
    local max_prog_type_len=0
    local max_attach_type_len=0
    local max_section_len=0
    local max_alias_len=0
    local max_flags_len=0

    # Calculate header lengths
    local header_prog="Program Type"
    local header_attach="Attach Type"
    local header_section="Section Name"
    local header_aliases="Aliases"
    local header_flags="Flags"

    max_prog_type_len=${#header_prog}
    max_attach_type_len=${#header_attach}
    max_section_len=${#header_section}
    max_alias_len=${#header_aliases}
    max_flags_len=${#header_flags}

    for canonical_name in $(printf '%s\n' "${!BPF_PROGRAM_TYPE_ALIASES[@]}" | sort); do
        # Get program type and attach type
        local prog_type=""
        local attach_type=""
        if [[ -n "${BPF_KERNEL_CONSTANTS[${canonical_name}]:-}" ]]; then
            local constants="${BPF_KERNEL_CONSTANTS[${canonical_name}]}"
            if [[ "${constants}" =~ ^([^:]+):(.+)$ ]]; then
                prog_type="${BASH_REMATCH[1]}"
                attach_type="${BASH_REMATCH[2]}"
            else
                prog_type="${constants}"
                attach_type="(none)"
            fi
        fi

        # Update max lengths
        if [[ ${#prog_type} -gt ${max_prog_type_len} ]]; then
            max_prog_type_len=${#prog_type}
        fi
        if [[ ${#attach_type} -gt ${max_attach_type_len} ]]; then
            max_attach_type_len=${#attach_type}
        fi
        if [[ ${#canonical_name} -gt ${max_section_len} ]]; then
            max_section_len=${#canonical_name}
        fi

        # Build alias list
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        local alias_list=""
        for alias in ${aliases}; do
            local literal_alias="${alias//\[\.\]/.}"
            if [[ "${literal_alias}" != "${canonical_name}" ]]; then
                if [[ -z "${alias_list}" ]]; then
                    alias_list="${literal_alias}"
                else
                    alias_list="${alias_list}, ${literal_alias}"
                fi
            fi
        done

        if [[ ${#alias_list} -gt ${max_alias_len} ]]; then
            max_alias_len=${#alias_list}
        fi

        # Get flags
        local flags="${BPF_SECTION_FLAGS[${canonical_name}]:-SEC_NONE}"
        if [[ ${#flags} -gt ${max_flags_len} ]]; then
            max_flags_len=${#flags}
        fi
    done

    # Add padding
    max_prog_type_len=$((max_prog_type_len + 2))
    max_attach_type_len=$((max_attach_type_len + 2))
    max_section_len=$((max_section_len + 2))
    max_alias_len=$((max_alias_len + 2))
    max_flags_len=$((max_flags_len + 2))

    # Print header
    printf "  %-${max_prog_type_len}s  %-${max_attach_type_len}s  %-${max_section_len}s  %-${max_alias_len}s  %-${max_flags_len}s\n" \
        "${header_prog}" "${header_attach}" "${header_section}" "${header_aliases}" "${header_flags}"
    printf "  %-${max_prog_type_len}s  %-${max_attach_type_len}s  %-${max_section_len}s  %-${max_alias_len}s  %-${max_flags_len}s\n" \
        "$(printf '%*s' ${max_prog_type_len} | tr ' ' '-')" \
        "$(printf '%*s' ${max_attach_type_len} | tr ' ' '-')" \
        "$(printf '%*s' ${max_section_len} | tr ' ' '-')" \
        "$(printf '%*s' ${max_alias_len} | tr ' ' '-')" \
        "$(printf '%*s' ${max_flags_len} | tr ' ' '-')"

    # Second pass: print all entries
    for canonical_name in $(printf '%s\n' "${!BPF_PROGRAM_TYPE_ALIASES[@]}" | sort); do
        # Get program type and attach type
        local prog_type=""
        local attach_type=""
        if [[ -n "${BPF_KERNEL_CONSTANTS[${canonical_name}]:-}" ]]; then
            local constants="${BPF_KERNEL_CONSTANTS[${canonical_name}]}"
            if [[ "${constants}" =~ ^([^:]+):(.+)$ ]]; then
                prog_type="${BASH_REMATCH[1]}"
                attach_type="${BASH_REMATCH[2]}"
            else
                prog_type="${constants}"
                attach_type="(none)"
            fi
        else
            prog_type="(unknown)"
            attach_type="(unknown)"
        fi

        # Build alias list
        local aliases="${BPF_PROGRAM_TYPE_ALIASES[${canonical_name}]}"
        local alias_list=""
        for alias in ${aliases}; do
            local literal_alias="${alias//\[\.\]/.}"
            if [[ "${literal_alias}" != "${canonical_name}" ]]; then
                if [[ -z "${alias_list}" ]]; then
                    alias_list="${literal_alias}"
                else
                    alias_list="${alias_list}, ${literal_alias}"
                fi
            fi
        done

        # Get flags
        local flags="${BPF_SECTION_FLAGS[${canonical_name}]:-SEC_NONE}"

        # Print row
        printf "  %-${max_prog_type_len}s  %-${max_attach_type_len}s  %-${max_section_len}s  %-${max_alias_len}s  %-${max_flags_len}s\n" \
            "${prog_type}" "${attach_type}" "${canonical_name}" "${alias_list:-}" "${flags}"
    done
    echo ""
    echo "Flag explanations:"
    echo "  SEC_NONE              - No special flags"
    echo "  SEC_ATTACHABLE        - Legacy attachable (BPF_PROG_ATTACH)"
    echo "  SEC_ATTACHABLE_OPT    - Attachable with optional attach type"
    echo "  SEC_ATTACH_BTF        - Attachment target via BTF ID"
    echo "  SEC_SLEEPABLE         - Program allows sleeping/blocking in kernel"
    echo "  SEC_XDP_FRAGS         - Supports non-linear XDP buffer"
    echo "  SEC_USDT              - USDT probe attachment"
    echo "  (Combined flags shown as: FLAG1|FLAG2)"
    echo ""
    echo "Usage examples:"
    echo "  --match-section xdp          # Matches section names starting with 'xdp' (and aliases)"
    echo "  --match-section 'xdp/*'      # Matches all section names starting with 'xdp/*' (including aliases)"
    echo "  --match-section xdp/cpumap   # Matches section name 'xdp/cpumap' (and aliases if any)"
}

# Parse command-line arguments
# Modifies global variables: DUMP, MEASURE, SHOW_SOURCE, SHOW_LINES, SHOW_SUMMARY,
# COMPARE_MODE, BASELINE_FILE, NEW_FILE, SECTION, EXPLICIT_DUMP, EXPLICIT_MEASURE, MATCH_SECTION
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d | --dump)
                DUMP=true
                EXPLICIT_DUMP=true
                # Only disable measure if not explicitly requested
                if [[ "${EXPLICIT_MEASURE}" = false ]]; then
                    MEASURE=false
                fi
                shift
                ;;
            -m | --measure)
                MEASURE=true
                EXPLICIT_MEASURE=true
                shift
                ;;
            -a | --all)
                DUMP=true
                MEASURE=true
                EXPLICIT_DUMP=true
                EXPLICIT_MEASURE=true
                shift
                ;;
            -s | --source)
                SHOW_SOURCE=true
                shift
                ;;
            -l | --lines)
                SHOW_LINES=true
                shift
                ;;
            --summary)
                SHOW_SUMMARY=true
                shift
                ;;
            --match-section)
                if [[ -z "${2:-}" ]]; then
                    die "--match-section requires a pattern argument. Usage: --match-section 'pattern'"
                fi
                MATCH_SECTION="$2"
                shift 2
                ;;
            --list-sections)
                list_match_options
                exit 0
                ;;
            -c | --compare)
                COMPARE_MODE=true
                if [[ -z "${2:-}" ]] || [[ -z "${3:-}" ]]; then
                    error "--compare requires two arguments: baseline_file new_file"
                    error "Usage: $0 --compare baseline.bpf.o new.bpf.o"
                    exit 1
                fi
                BASELINE_FILE="$2"
                NEW_FILE="$3"
                shift 3
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                error "Use -h or --help for usage information"
                exit 1
                ;;
            *)
                SECTION="$1"
                shift
                ;;
        esac
    done
}

# Main function containing the script's primary logic
main() {
    # Handle compare mode
    if [[ "${COMPARE_MODE}" = true ]]; then
        compare_files "${BASELINE_FILE}" "${NEW_FILE}"
        exit 0
    fi

    # Check if BPF object exists
    if [[ ! -f "${BPF_OBJ}" ]]; then
        error "BPF object file not found: ${BPF_OBJ}."
        die "Build it first with: make bpf"
    fi

    # Determine if we should process all sections
    # Default: measure all if no section specified
    # If section specified: measure that section only (unless -d or -a flags used)
    # If match-section is provided, it filters sections (overrides section specification)
    if [[ -n "${MATCH_SECTION}" ]]; then
        # Match-section mode: get all sections and filter by section pattern
        ALL_SECTIONS=true
        SECTIONS=$(get_all_sections)
        if [[ -z "${SECTIONS}" ]]; then
            die "No BPF program sections found matching section pattern: ${MATCH_SECTION}"
        fi
        # Count sections reliably
        SECTION_COUNT=$(count_sections "${SECTIONS}")
        if [[ "${SHOW_SUMMARY}" = false ]]; then
            if [[ "${MEASURE}" = true ]]; then
                info "Measuring ${SECTION_COUNT} BPF program section(s) matching pattern: ${MATCH_SECTION}"
            elif [[ "${DUMP}" = true ]]; then
                info "Dumping ${SECTION_COUNT} BPF program section(s) matching pattern: ${MATCH_SECTION}"
            fi
            info ""
        fi
    elif [[ -z "${SECTION}" ]]; then
        ALL_SECTIONS=true
        SECTIONS=$(get_all_sections)
        if [[ -z "${SECTIONS}" ]]; then
            die "No BPF program sections found in ${BPF_OBJ}"
        fi
        # Count sections reliably
        SECTION_COUNT=$(count_sections "${SECTIONS}")
        if [[ "${SHOW_SUMMARY}" = false ]]; then
            if [[ "${MEASURE}" = true ]]; then
                info "Measuring ${SECTION_COUNT} BPF program section(s)"
            elif [[ "${DUMP}" = true ]]; then
                info "Dumping ${SECTION_COUNT} BPF program section(s)"
            fi
            info ""
        fi
    else
        ALL_SECTIONS=false
        SECTIONS="${SECTION}"
        # If section specified, default to measure only (unless explicitly requested otherwise)
        if [[ "${EXPLICIT_DUMP}" = false ]] && [[ "${EXPLICIT_MEASURE}" = false ]]; then
            MEASURE=true
            DUMP=false
        fi
        # --summary requires measuring all sections
        if [[ "${SHOW_SUMMARY}" = true ]]; then
            die "--summary requires measuring all sections (no section specified). Use: $0 --summary"
        fi
    fi

    # --summary requires MEASURE to be enabled
    if [[ "${SHOW_SUMMARY}" = true ]] && [[ "${MEASURE}" = false ]]; then
        die "--summary requires measurement to be enabled. Use: $0 --summary (or $0 -m --summary)"
    fi

    # Process each section
    TOTAL_PROGRAM_SIZE=0
    TOTAL_INSN_SLOTS=0
    TOTAL_INSN_COUNT=0
    MEASURED_SECTION_SIZE=0
    MEASURED_INSN_SLOTS=0
    MEASURED_INSN_COUNT=0

    # Initialize associative arrays for probe type tracking (bash 4+ required)
    # Use -g to make them global so they're accessible to accumulate_totals()
    if [[ "${BASH_VERSION%%.*}" -ge 4 ]] && [[ "${SHOW_SUMMARY}" = true ]]; then
        declare -gA PROBE_TYPE_COUNTS
        declare -gA PROBE_TYPE_SIZES
    fi

    for section in ${SECTIONS}; do
        # Execute requested actions
        # When --summary is set, suppress all output except the final summary
        if [[ "${SHOW_SUMMARY}" = true ]]; then
            # Still measure to collect data, but suppress output
            if [[ "${MEASURE}" = true ]]; then
                measure_program "${section}" "${BPF_OBJ}" true
                accumulate_totals "${section}"
            fi
            # Don't dump when --summary is set
        elif [[ "${DUMP}" = true ]] && [[ "${MEASURE}" = true ]]; then
            measure_program "${section}"
            accumulate_totals "${section}"
            print_separator "="
            dump_assembly "${section}"
        elif [[ "${DUMP}" = true ]]; then
            dump_assembly "${section}"
        elif [[ "${MEASURE}" = true ]]; then
            measure_program "${section}"
            accumulate_totals "${section}"
            # Add blank line between sections when measuring all (except after last section)
            if [[ "${ALL_SECTIONS}" = true ]] && [[ "${section}" != $(echo "${SECTIONS}" | awk '{print $NF}') ]]; then
                info ""
            fi
        fi
    done

    # Get .o file size when measure is enabled
    OBJ_FILE_SIZE=""
    if [[ "${MEASURE}" = true ]] && [[ -f "${BPF_OBJ}" ]]; then
        OBJ_FILE_SIZE=$(get_file_size "${BPF_OBJ}")
        # get_file_size returns "0" if stat fails, but we want empty string for consistency
        if [[ "${OBJ_FILE_SIZE}" = "0" ]]; then
            OBJ_FILE_SIZE=""
        fi
    fi

    # Summary display
    # Show full summary when measuring all sections (with or without --summary flag)
    if [[ "${MEASURE}" = true ]] && [[ "${ALL_SECTIONS}" = true ]]; then
        # Add blank line before summary unless --summary flag was used (which already suppresses other output)
        if [[ "${SHOW_SUMMARY}" = false ]]; then
            info ""
        fi
        display_summary "${SECTION_COUNT}" "${TOTAL_PROGRAM_SIZE}" "${TOTAL_INSN_COUNT}" "${TOTAL_INSN_SLOTS}" "${OBJ_FILE_SIZE}" "${SHOW_SUMMARY}"
    # Show object file size and notes when measuring a single section
    elif [[ "${MEASURE}" = true ]] && [[ -n "${OBJ_FILE_SIZE}" ]]; then
        info ""
        info "Object file size: ${OBJ_FILE_SIZE} bytes ($(format_bytes "${OBJ_FILE_SIZE}"))"
        info ""
        info "Note: Each eBPF instruction is 8 bytes (64 bits)"
        info "Note: ldimm64 instructions span 2 instruction slots but show as 1 line in disassembly"
        info "Note: Instruction slots (0-indexed) represent the actual program size"
    fi
}

# Parse arguments and execute main logic
parse_args "$@"
main
