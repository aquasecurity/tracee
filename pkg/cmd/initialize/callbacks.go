package initialize

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/logger"
)

var (
	// triggered by: libbpf/src/nlattr.c->libbpf_nla_dump_errormsg()
	// "libbpf: Kernel error message: %s\n"
	// 1. %s = "Exclusivity flag on"
	libbpfgoKernelExclusivityFlagOnRegexp = regexp.MustCompile(`libbpf:.*Kernel error message:.*Exclusivity flag on`)

	// triggered by: libbpf/src/libbpf.c->bpf_program__attach_kprobe_opts()
	// "libbpf: prog '%s': failed to create %s '%s+0x%zx' perf event: %s\n"
	// 1. %s = trace_check_map_func_compatibility | trace_utimes_common
	// 2. %s = kretprobe or kprobe
	// 3. %s = check_map_func_compatibility (function name)
	// 4. %x = offset (ignored in this check)
	// 5. %s = No such file or directory
	libbpfgoKprobePerfEventRegexp = regexp.MustCompile(`libbpf:.*prog '(?:trace_check_map_func_compatibility|trace_utimes_common)'.*failed to create kprobe.*perf event: No such file or directory`)

	// triggered by: libbpf/src/libbpf.c->bpf_program__attach_fd()
	// "libbpf: prog '%s': failed to attach to %s: %s\n"
	// 1. %s = cgroup_skb_ingress or cgroup_skb_egress
	// 2. %s = cgroup
	// 3. %s = Invalid argument
	libbpfgoAttachCgroupRegexp = regexp.MustCompile(`libbpf:.*prog 'cgroup_skb_ingress|cgroup_skb_egress'.*failed to attach to cgroup.*Invalid argument`)

	// triggered by: libbpf/src/libbpf.c->bpf_object__create_map()
	// "libbpf: Error in bpf_create_map_xattr(%s)\n"
	// 1. %s = sys_enter_init_tail
	// 2. %s = sys_enter_submit_tail
	// 3. %s = sys_enter_tails
	// 4. %s = sys_exit_init_tail
	// 5. %s = sys_exit_submit_tail
	// 6. %s = sys_exit_tails
	// 7. %s = prog_array_tp
	// 8. %s = prog_array
	libbpfgoBpfCreateMapXattrRegexp = regexp.MustCompile(`libbpf:.*bpf_create_map_xattr\((sys_enter_init_tail|sys_enter_submit_tail|sys_enter_tails|sys_exit_init_tail|sys_exit_submit_tail|sys_exit_tails|prog_array_tp|prog_array)\)`)
)

// SetLibbpfgoCallbacks sets libbpfgo logger callbacks
func SetLibbpfgoCallbacks() {
	libbpfgo.SetLoggerCbs(libbpfgo.Callbacks{
		Log: func(libLevel int, msg string) {
			// Output a formatted eBPF program loading failure only via stderr,
			// leaving the previous output "BPF program load failed:" to the logger, which is
			// sufficient for the log consumer to identify the error.
			if libLevel == libbpfgo.LibbpfWarnLevel && strings.Contains(msg, "-- BEGIN PROG LOAD LOG --") {
				fmt.Fprintf(os.Stderr, "%s", msg)
				return
			}

			lvl := logger.ErrorLevel

			switch libLevel {
			case libbpfgo.LibbpfWarnLevel:
				lvl = logger.WarnLevel
			case libbpfgo.LibbpfInfoLevel:
				lvl = logger.InfoLevel
			case libbpfgo.LibbpfDebugLevel:
				lvl = logger.DebugLevel
			}

			msg = strings.TrimSuffix(msg, "\n")
			logger.Log(lvl, false, msg)
		},
		LogFilters: []func(libLevel int, msg string) bool{
			// Ignore libbpf outputs that are not relevant to tracee
			func(libLevel int, msg string) bool {
				if libLevel != libbpfgo.LibbpfWarnLevel {
					return true
				}

				// BUG: https:/github.com/aquasecurity/tracee/issues/1676
				if libbpfgoKernelExclusivityFlagOnRegexp.MatchString(msg) {
					return true
				}

				// BUGS: https://github.com/aquasecurity/tracee/issues/2446
				//       https://github.com/aquasecurity/tracee/issues/2754
				if libbpfgoKprobePerfEventRegexp.MatchString(msg) {
					return true
				}

				// AttachCgroupLegacy() will first try AttachCgroup() and it might fail. This
				// is not an error and is the best way of probing for eBPF cgroup attachment
				// link existence.
				if libbpfgoAttachCgroupRegexp.MatchString(msg) {
					return true
				}

				// BUG: https://github.com/aquasecurity/tracee/issues/1602
				if libbpfgoBpfCreateMapXattrRegexp.MatchString(msg) {
					return true
				}

				// output is not filtered
				return false
			},
		},
	})
}
