package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

type fdArgTask struct {
	PID uint32
	TID uint32
	FD  int32
}

func ParseArgs(event *trace.Event) error {
	for i := range event.Args {
		if ptr, isUintptr := event.Args[i].Value.(uintptr); isUintptr {
			event.Args[i].Value = "0x" + strconv.FormatUint(uint64(ptr), 16)
		}
	}

	EmptyString := func(arg *trace.Argument) {
		arg.Type = "string"
		arg.Value = ""
	}

	ParseOrEmptyString := func(arg *trace.Argument, sysArg helpers.SystemFunctionArgument, err error) {
		EmptyString(arg)
		if err == nil {
			arg.Value = sysArg.String()
		}
	}

	switch ID(event.EventID) {
	case MemProtAlert:
		if alertArg := GetArg(event, "alert"); alertArg != nil {
			if alert, isUint32 := alertArg.Value.(uint32); isUint32 {
				alertArg.Value = trace.MemProtAlert(alert).String()
				alertArg.Type = "string"
			}
		}
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				ParseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case SysEnter, SysExit:
		if syscallArg := GetArg(event, "syscall"); syscallArg != nil {
			if id, isInt32 := syscallArg.Value.(int32); isInt32 {
				if event, isKnown := Definitions.GetSafe(ID(id)); isKnown {
					if event.Syscall {
						syscallArg.Value = event.Name
						syscallArg.Type = "string"
					}
				}
			}
		}
		if ID(event.EventID) == CapCapable {
			if capArg := GetArg(event, "cap"); capArg != nil {
				if capability, isInt32 := capArg.Value.(int32); isInt32 {
					capabilityFlagArgument, err := helpers.ParseCapability(uint64(capability))
					ParseOrEmptyString(capArg, capabilityFlagArgument, err)
				}
			}
		}
	case SecurityMmapFile, DoMmap:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isUint64 := protArg.Value.(uint64); isUint64 {
				mmapProtArgument := helpers.ParseMmapProt(prot)
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
	case SecurityFileMprotect:
		if protArg := GetArg(event, "prot"); protArg != nil {
			if prot, isInt32 := protArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prot))
				ParseOrEmptyString(protArg, mmapProtArgument, nil)
			}
		}
		if prevProtArg := GetArg(event, "prev_prot"); prevProtArg != nil {
			if prevProt, isInt32 := prevProtArg.Value.(int32); isInt32 {
				mmapProtArgument := helpers.ParseMmapProt(uint64(prevProt))
				ParseOrEmptyString(prevProtArg, mmapProtArgument, nil)
			}
		}
	case Ptrace:
		if reqArg := GetArg(event, "request"); reqArg != nil {
			if req, isInt64 := reqArg.Value.(int64); isInt64 {
				ptraceRequestArgument, err := helpers.ParsePtraceRequestArgument(uint64(req))
				ParseOrEmptyString(reqArg, ptraceRequestArgument, err)
			}
		}
	case Prctl:
		if optArg := GetArg(event, "option"); optArg != nil {
			if opt, isInt32 := optArg.Value.(int32); isInt32 {
				prctlOptionArgument, err := helpers.ParsePrctlOption(uint64(opt))
				ParseOrEmptyString(optArg, prctlOptionArgument, err)
			}
		}
	case Socket:
		if domArg := GetArg(event, "domain"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case SecuritySocketCreate:
		if domArg := GetArg(event, "family"); domArg != nil {
			if dom, isInt32 := domArg.Value.(int32); isInt32 {
				socketDomainArgument, err := helpers.ParseSocketDomainArgument(uint64(dom))
				ParseOrEmptyString(domArg, socketDomainArgument, err)
			}
		}
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if typ, isInt32 := typeArg.Value.(int32); isInt32 {
				socketTypeArgument, err := helpers.ParseSocketType(uint64(typ))
				ParseOrEmptyString(typeArg, socketTypeArgument, err)
			}
		}
	case Access, Faccessat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isInt32 := modeArg.Value.(int32); isInt32 {
				accessModeArgument, err := helpers.ParseAccessMode(uint64(mode))
				ParseOrEmptyString(modeArg, accessModeArgument, err)
			}
		}
	case Execveat:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				execFlagArgument, err := helpers.ParseExecFlag(uint64(flags))
				ParseOrEmptyString(flagsArg, execFlagArgument, err)
			}
		}
	case Open, Openat, SecurityFileOpen:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isInt32 := flagsArg.Value.(int32); isInt32 {
				openFlagArgument, err := helpers.ParseOpenFlagArgument(uint64(flags))
				ParseOrEmptyString(flagsArg, openFlagArgument, err)
			}
		}
	case Mknod, Mknodat, Chmod, Fchmod, Fchmodat:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint32 := modeArg.Value.(uint32); isUint32 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecurityInodeMknod:
		if modeArg := GetArg(event, "mode"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case Clone:
		if flagsArg := GetArg(event, "flags"); flagsArg != nil {
			if flags, isUint64 := flagsArg.Value.(uint64); isUint64 {
				cloneFlagArgument, err := helpers.ParseCloneFlags(uint64(flags))
				ParseOrEmptyString(flagsArg, cloneFlagArgument, err)
			}
		}
	case Bpf, SecurityBPF:
		if cmdArg := GetArg(event, "cmd"); cmdArg != nil {
			if cmd, isInt32 := cmdArg.Value.(int32); isInt32 {
				bpfCommandArgument, err := helpers.ParseBPFCmd(uint64(cmd))
				ParseOrEmptyString(cmdArg, bpfCommandArgument, err)
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if typeArg := GetArg(event, "type"); typeArg != nil {
			if readFileId, isInt32 := typeArg.Value.(trace.KernelReadType); isInt32 {
				EmptyString(typeArg)
				typeArg.Value = readFileId.String()
			}
		}
	case SchedProcessExec:
		if modeArg := GetArg(event, "stdin_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case DirtyPipeSplice:
		if modeArg := GetArg(event, "in_file_type"); modeArg != nil {
			if mode, isUint16 := modeArg.Value.(uint16); isUint16 {
				inodeModeArgument, err := helpers.ParseInodeMode(uint64(mode))
				ParseOrEmptyString(modeArg, inodeModeArgument, err)
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if levelArg := GetArg(event, "level"); levelArg != nil {
			if level, isInt := levelArg.Value.(int32); isInt {
				levelArgument, err := helpers.ParseSocketLevel(uint64(level))
				ParseOrEmptyString(levelArg, levelArgument, err)
			}
		}
		if optionNameArg := GetArg(event, "optname"); optionNameArg != nil {
			if opt, isInt := optionNameArg.Value.(int32); isInt {
				var optionNameArgument helpers.SocketOptionArgument
				var err error
				if ID(event.EventID) == Getsockopt {
					optionNameArgument, err = helpers.ParseGetSocketOption(uint64(opt))
				} else {
					optionNameArgument, err = helpers.ParseSetSocketOption(uint64(opt))
				}
				ParseOrEmptyString(optionNameArg, optionNameArgument, err)
			}
		}
	case BpfAttach:
		if progTypeArg := GetArg(event, "prog_type"); progTypeArg != nil {
			if progType, isInt := progTypeArg.Value.(int32); isInt {
				progTypeArgument, err := helpers.ParseBPFProgType(uint64(progType))
				ParseOrEmptyString(progTypeArg, progTypeArgument, err)
			}
		}
		if helpersArg := GetArg(event, "prog_helpers"); helpersArg != nil {
			if helpersList, isUintSlice := helpersArg.Value.([]uint64); isUintSlice {
				parsedHelpersList, err := parseBpfAttachHelperUsage(helpersList)
				if err != nil {
					return err
				}
				helpersArg.Type = "char*"
				helpersArg.Value = parsedHelpersList
			}
		}
		if perfTypeArg := GetArg(event, "perf_type"); perfTypeArg != nil {
			if perfType, isInt := perfTypeArg.Value.(int32); isInt {
				perfTypestr, err := parseBpfAttachPerfType(perfType)
				EmptyString(perfTypeArg)
				if err == nil {
					perfTypeArg.Value = perfTypestr
				}
			}
		}
	}

	return nil
}

func ParseArgsFDs(event *trace.Event, fdArgPathMap *bpf.BPFMap) error {
	if fdArg := GetArg(event, "fd"); fdArg != nil {
		if fd, isInt32 := fdArg.Value.(int32); isInt32 {
			fdArgTask := &fdArgTask{
				PID: uint32(event.ProcessID),
				TID: uint32(event.ThreadID),
				FD:  fd,
			}
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(fdArgTask))
			if err != nil {
				return errfmt.WrapError(err)
			}

			fpath := string(bytes.Trim(bs, "\x00"))
			fdArg.Value = fmt.Sprintf("%d=%s", fd, fpath)
		}
	}

	return nil
}

func GetArg(event *trace.Event, argName string) *trace.Argument {
	for i := range event.Args {
		if event.Args[i].Name == argName {
			return &event.Args[i]
		}
	}
	return nil
}

type CustomFunctionArgument struct {
	val uint64
	str string
}

func (arg CustomFunctionArgument) String() string {
	return arg.str
}
func (arg CustomFunctionArgument) Value() uint64 {
	return arg.val
}

func parseBpfAttachHelperUsage(helperList []uint64) ([]string, error) {

	var usedHelpers []string

	for idx, helperName := range BpfHelpers {
		if (helperList[idx/64] & (1 << (idx % 64))) > 0 {
			usedHelpers = append(usedHelpers, helperName)
		}
	}

	return usedHelpers, nil
}

var BpfHelpers = []string{
	"unspec",
	"map_lookup_elem",
	"map_update_elem",
	"map_delete_elem",
	"probe_read",
	"ktime_get_ns",
	"trace_printk",
	"get_prandom_u32",
	"get_smp_processor_id",
	"skb_store_bytes",
	"l3_csum_replace",
	"l4_csum_replace",
	"tail_call",
	"clone_redirect",
	"get_current_pid_tgid",
	"get_current_uid_gid",
	"get_current_comm",
	"get_cgroup_classid",
	"skb_vlan_push",
	"skb_vlan_pop",
	"skb_get_tunnel_key",
	"skb_set_tunnel_key",
	"perf_event_read",
	"redirect",
	"get_route_realm",
	"perf_event_output",
	"skb_load_bytes",
	"get_stackid",
	"csum_diff",
	"skb_get_tunnel_opt",
	"skb_set_tunnel_opt",
	"skb_change_proto",
	"skb_change_type",
	"skb_under_cgroup",
	"get_hash_recalc",
	"get_current_task",
	"probe_write_user",
	"current_task_under_cgroup",
	"skb_change_tail",
	"skb_pull_data",
	"csum_update",
	"set_hash_invalid",
	"get_numa_node_id",
	"skb_change_head",
	"xdp_adjust_head",
	"probe_read_str",
	"get_socket_cookie",
	"get_socket_uid",
	"set_hash",
	"setsockopt",
	"skb_adjust_room",
	"redirect_map",
	"sk_redirect_map",
	"sock_map_update",
	"xdp_adjust_meta",
	"perf_event_read_value",
	"perf_prog_read_value",
	"getsockopt",
	"override_return",
	"sock_ops_cb_flags_set",
	"msg_redirect_map",
	"msg_apply_bytes",
	"msg_cork_bytes",
	"msg_pull_data",
	"bind",
	"xdp_adjust_tail",
	"skb_get_xfrm_state",
	"get_stack",
	"skb_load_bytes_relative",
	"fib_lookup",
	"sock_hash_update",
	"msg_redirect_hash",
	"sk_redirect_hash",
	"lwt_push_encap",
	"lwt_seg6_store_bytes",
	"lwt_seg6_adjust_srh",
	"lwt_seg6_action",
	"rc_repeat",
	"rc_keydown",
	"skb_cgroup_id",
	"get_current_cgroup_id",
	"get_local_storage",
	"sk_select_reuseport",
	"skb_ancestor_cgroup_id",
	"sk_lookup_tcp",
	"sk_lookup_udp",
	"sk_release",
	"map_push_elem",
	"map_pop_elem",
	"map_peek_elem",
	"msg_push_data",
	"msg_pop_data",
	"rc_pointer_rel",
	"spin_lock",
	"spin_unlock",
	"sk_fullsock",
	"tcp_sock",
	"skb_ecn_set_ce",
	"get_listener_sock",
	"skc_lookup_tcp",
	"tcp_check_syncookie",
	"sysctl_get_name",
	"sysctl_get_current_value",
	"sysctl_get_new_value",
	"sysctl_set_new_value",
	"strtol",
	"strtoul",
	"sk_storage_get",
	"sk_storage_delete",
	"send_signal",
	"tcp_gen_syncookie",
	"skb_output",
	"probe_read_user",
	"probe_read_kernel",
	"probe_read_user_str",
	"probe_read_kernel_str",
	"tcp_send_ack",
	"send_signal_thread",
	"jiffies64",
	"read_branch_records",
	"get_ns_current_pid_tgid",
	"xdp_output",
	"get_netns_cookie",
	"get_current_ancestor_cgroup_id",
	"sk_assign",
	"ktime_get_boot_ns",
	"seq_printf",
	"seq_write",
	"sk_cgroup_id",
	"sk_ancestor_cgroup_id",
	"ringbuf_output",
	"ringbuf_reserve",
	"ringbuf_submit",
	"ringbuf_discard",
	"ringbuf_query",
	"csum_level",
	"skc_to_tcp6_sock",
	"skc_to_tcp_sock",
	"skc_to_tcp_timewait_sock",
	"skc_to_tcp_request_sock",
	"skc_to_udp6_sock",
	"get_task_stack",
	"load_hdr_opt",
	"store_hdr_opt",
	"reserve_hdr_opt",
	"inode_storage_get",
	"inode_storage_delete",
	"d_path",
	"copy_from_user",
	"snprintf_btf",
	"seq_printf_btf",
	"skb_cgroup_classid",
	"redirect_neigh",
	"per_cpu_ptr",
	"this_cpu_ptr",
	"redirect_peer",
	"task_storage_get",
	"task_storage_delete",
	"get_current_task_btf",
	"bprm_opts_set",
	"ktime_get_coarse_ns",
	"ima_inode_hash",
	"sock_from_file",
	"check_mtu",
	"for_each_map_elem",
	"snprintf",
	"sys_bpf",
	"btf_find_by_name_kind",
	"sys_close",
	"timer_init",
	"timer_set_callback",
	"timer_start",
	"timer_cancel",
	"get_func_ip",
	"get_attach_cookie",
	"task_pt_regs",
	"get_branch_snapshot",
	"trace_vprintk",
	"skc_to_unix_sock",
	"kallsyms_lookup_name",
	"find_vma",
	"loop",
	"strncmp",
	"get_func_arg",
	"get_func_ret",
	"get_func_arg_cnt",
	"get_retval",
	"set_retval",
	"xdp_get_buff_len",
	"xdp_load_bytes",
	"xdp_store_bytes",
	"copy_from_user_task",
	"skb_set_tstamp",
	"ima_file_hash",
	"kptr_xchg",
	"map_lookup_percpu_elem",
	"skc_to_mptcp_sock",
	"dynptr_from_mem",
	"ringbuf_reserve_dynptr",
	"ringbuf_submit_dynptr",
	"ringbuf_discard_dynptr",
	"dynptr_read",
	"dynptr_write",
	"dynptr_data",
	"tcp_raw_gen_syncookie_ipv4",
	"tcp_raw_gen_syncookie_ipv6",
	"tcp_raw_check_syncookie_ipv4",
	"tcp_raw_check_syncookie_ipv6",
	"ktime_get_tai_ns",
	"user_ringbuf_drain",
	"cgrp_storage_get",
	"cgrp_storage_delete",
}

func parseBpfAttachPerfType(perfType int32) (string, error) {
	switch perfType {
	case 0:
		return "tracepoint", nil
	case 1:
		return "kprobe", nil
	case 2:
		return "kretprobe", nil
	case 3:
		return "uprobe", nil
	case 4:
		return "uretprobe", nil
	default:
		return "", errfmt.Errorf("unknown perf_type got from bpf_attach event")
	}
}
