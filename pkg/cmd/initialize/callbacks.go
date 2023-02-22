package initialize

import (
	"regexp"

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
	libbpfgoAttachCgroupregexp = regexp.MustCompile(`libbpf:.*prog 'cgroup_skb_ingress|cgroup_skb_egress'.*failed to attach to cgroup.*Invalid argument`)
)

// SetLibbpfgoCallbacks sets libbpfgo logger callbacks
func SetLibbpfgoCallbacks() {
	libbpfgo.SetLoggerCbs(libbpfgo.Callbacks{
		Log: func(libLevel int, msg string) {
			lvl := logger.ErrorLevel

			switch libLevel {
			case libbpfgo.LibbpfWarnLevel:
				lvl = logger.WarnLevel
			case libbpfgo.LibbpfInfoLevel:
				lvl = logger.InfoLevel
			case libbpfgo.LibbpfDebugLevel:
				lvl = logger.DebugLevel
			}

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
				if libbpfgoAttachCgroupregexp.MatchString(msg) {
					return true
				}

				// output is not filtered
				return false
			},
		},
	})
}
