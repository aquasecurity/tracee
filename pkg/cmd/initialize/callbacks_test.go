package initialize

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/logger"
)

func Test_translateLibbpfLogLevel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		libLevel int
		expected logger.Level
	}{
		{
			name:     "WarnLevel",
			libLevel: libbpfgo.LibbpfWarnLevel,
			expected: logger.WarnLevel,
		},
		{
			name:     "InfoLevel",
			libLevel: libbpfgo.LibbpfInfoLevel,
			expected: logger.InfoLevel,
		},
		{
			name:     "DebugLevel",
			libLevel: libbpfgo.LibbpfDebugLevel,
			expected: logger.DebugLevel,
		},
		{
			name:     "ErrorLevel_Default",
			libLevel: 999, // Unknown level defaults to error
			expected: logger.ErrorLevel,
		},
		{
			name:     "WarnLevel_Zero",
			libLevel: 0, // Zero is actually LibbpfWarnLevel
			expected: logger.WarnLevel,
		},
		{
			name:     "ErrorLevel_Negative",
			libLevel: -1, // Negative level defaults to error
			expected: logger.ErrorLevel,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := translateLibbpfLogLevel(tc.libLevel)
			assert.Equal(t, tc.expected, result, "Should translate log level correctly")
		})
	}
}

func Test_libbpfgoLogFilterCallback(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		libLevel     int
		message      string
		shouldFilter bool
		description  string
	}{
		// TRUE cases - messages that should be filtered (return true)
		{
			name:         "KernelExclusivityFlagOn_Exact",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Kernel error message: Exclusivity flag on",
			shouldFilter: true,
			description:  "Should filter kernel exclusivity flag messages",
		},
		{
			name:         "KernelExclusivityFlagOn_WithPrefix",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: some prefix Kernel error message: Exclusivity flag on",
			shouldFilter: true,
			description:  "Should filter kernel exclusivity flag messages with prefix",
		},
		{
			name:         "KprobePerfEvent_TraceCheckMapFunc",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: No such file or directory",
			shouldFilter: true,
			description:  "Should filter kprobe perf event failures for trace_check_map_func_compatibility",
		},
		{
			name:         "KprobePerfEvent_TraceUtimesCommon",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'trace_utimes_common': failed to create kprobe 'utimes_common+0x10' perf event: No such file or directory",
			shouldFilter: true,
			description:  "Should filter kprobe perf event failures for trace_utimes_common",
		},
		{
			name:         "AttachCgroup_Ingress",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup: Invalid argument",
			shouldFilter: true,
			description:  "Should filter cgroup attachment failures for ingress",
		},
		{
			name:         "AttachCgroup_Egress",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'cgroup_skb_egress': failed to attach to cgroup: Invalid argument",
			shouldFilter: true,
			description:  "Should filter cgroup attachment failures for egress",
		},
		{
			name:         "BpfCreateMapXattr_SysEnterInitTail",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Error in bpf_create_map_xattr(sys_enter_init_tail)",
			shouldFilter: true,
			description:  "Should filter bpf_create_map_xattr errors for sys_enter_init_tail",
		},
		{
			name:         "BpfCreateMapXattr_ProgArray",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Error in bpf_create_map_xattr(prog_array)",
			shouldFilter: true,
			description:  "Should filter bpf_create_map_xattr errors for prog_array",
		},
		{
			name:         "BpfCreateMapXattr_SysExitTails",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Error in bpf_create_map_xattr(sys_exit_tails)",
			shouldFilter: true,
			description:  "Should filter bpf_create_map_xattr errors for sys_exit_tails",
		},
		{
			name:         "CreateUprobe",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: No such file or directory",
			shouldFilter: true,
			description:  "Should filter uprobe creation failures",
		},
		{
			name:         "CreateUretprobe",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'test_prog': failed to create uretprobe '/path/to/binary:0x2000' perf event: No such file or directory",
			shouldFilter: true,
			description:  "Should filter uretprobe creation failures",
		},
		{
			name:         "MissingBTFLineInfo_Exact",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			shouldFilter: true,
			description:  "Should filter missing BTF line info warnings",
		},
		{
			name:         "MissingBTFLineInfo_DifferentProgram",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'another_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			shouldFilter: true,
			description:  "Should filter missing BTF line info warnings for different programs",
		},
		{
			name:         "NonWarnLevel_Info",
			libLevel:     libbpfgo.LibbpfInfoLevel,
			message:      "libbpf: info message",
			shouldFilter: true,
			description:  "Should always filter non-warn level messages (info)",
		},
		{
			name:         "NonWarnLevel_Debug",
			libLevel:     libbpfgo.LibbpfDebugLevel,
			message:      "libbpf: debug message",
			shouldFilter: true,
			description:  "Should always filter non-warn level messages (debug)",
		},
		{
			name:         "NonWarnLevel_Error",
			libLevel:     999, // Unknown level
			message:      "libbpf: error message",
			shouldFilter: true,
			description:  "Should always filter non-warn level messages (unknown)",
		},

		// FALSE cases - messages that should NOT be filtered (return false)
		{
			name:         "UnfilteredWarning_Generic",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: some other warning message",
			shouldFilter: false,
			description:  "Should not filter unmatched warning messages",
		},
		{
			name:         "UnfilteredWarning_SimilarButDifferent",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Kernel error message: Different flag",
			shouldFilter: false,
			description:  "Should not filter similar but different kernel messages",
		},
		{
			name:         "UnfilteredWarning_WrongProgram",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'other_program': failed to create kprobe 'other_func+0x0' perf event: No such file or directory",
			shouldFilter: false,
			description:  "Should not filter kprobe messages for non-matching programs",
		},
		{
			name:         "UnfilteredWarning_WrongCgroupProgram",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'other_program': failed to attach to cgroup: Invalid argument",
			shouldFilter: false,
			description:  "Should not filter cgroup messages for non-matching programs",
		},
		{
			name:         "UnfilteredWarning_WrongMapName",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: Error in bpf_create_map_xattr(other_map)",
			shouldFilter: false,
			description:  "Should not filter bpf_create_map_xattr for non-matching map names",
		},
		{
			name:         "UnfilteredWarning_WrongUprobeError",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: Permission denied",
			shouldFilter: false,
			description:  "Should not filter uprobe messages with different errors",
		},
		{
			name:         "UnfilteredWarning_WrongBTFMessage",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: prog 'test_program': some other BTF related message",
			shouldFilter: false,
			description:  "Should not filter different BTF messages",
		},
		{
			name:         "UnfilteredWarning_NotLibbpf",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "other: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			shouldFilter: false,
			description:  "Should not filter messages not from libbpf",
		},
		{
			name:         "UnfilteredWarning_RandomMessage",
			libLevel:     libbpfgo.LibbpfWarnLevel,
			message:      "libbpf: completely unrelated warning message",
			shouldFilter: false,
			description:  "Should not filter completely unrelated warning messages",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			filtered := libbpfgoLogFilterCallback(tc.libLevel, tc.message)
			if tc.shouldFilter {
				assert.True(t, filtered, tc.description)
			} else {
				assert.False(t, filtered, tc.description)
			}
		})
	}
}

func Test_libbpfgoKernelExclusivityFlagOnRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		{
			name:    "ExactMatch",
			message: "libbpf: Kernel error message: Exclusivity flag on",
			matches: true,
		},
		{
			name:    "WithPrefix",
			message: "libbpf: some prefix Kernel error message: Exclusivity flag on",
			matches: true,
		},
		{
			name:    "NoMatch_DifferentMessage",
			message: "libbpf: Kernel error message: Different flag",
			matches: false,
		},
		{
			name:    "NoMatch_NotLibbpf",
			message: "other: Kernel error message: Exclusivity flag on",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: Kernel error message: Exclusivity flag on extra",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: Kernel error message: Exclusivity flag on",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoKernelExclusivityFlagOnRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "Kernel exclusivity flag regex should match expected result")
		})
	}
}

func Test_libbpfgoKprobePerfEventRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		{
			name:    "TraceCheckMapFuncCompatibility",
			message: "libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: No such file or directory",
			matches: true,
		},
		{
			name:    "TraceUtimesCommon",
			message: "libbpf: prog 'trace_utimes_common': failed to create kprobe 'utimes_common+0x10' perf event: No such file or directory",
			matches: true,
		},
		{
			name:    "NoMatch_DifferentProgram",
			message: "libbpf: prog 'other_program': failed to create kprobe 'other_func+0x0' perf event: No such file or directory",
			matches: false,
		},
		{
			name:    "NoMatch_DifferentError",
			message: "libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: Permission denied",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: No such file or directory extra",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: prog 'trace_check_map_func_compatibility': failed to create kprobe 'check_map_func_compatibility+0x0' perf event: No such file or directory",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoKprobePerfEventRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "Kprobe perf event regex should match expected result")
		})
	}
}

func Test_libbpfgoAttachCgroupRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		{
			name:    "CgroupSkbIngress",
			message: "libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup: Invalid argument",
			matches: true,
		},
		{
			name:    "CgroupSkbEgress",
			message: "libbpf: prog 'cgroup_skb_egress': failed to attach to cgroup: Invalid argument",
			matches: true,
		},
		{
			name:    "NoMatch_DifferentProgram",
			message: "libbpf: prog 'other_program': failed to attach to cgroup: Invalid argument",
			matches: false,
		},
		{
			name:    "NoMatch_DifferentError",
			message: "libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup: Permission denied",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup: Invalid argument extra",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: prog 'cgroup_skb_ingress': failed to attach to cgroup: Invalid argument",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoAttachCgroupRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "Attach cgroup regex should match expected result")
		})
	}
}

func Test_libbpfgoBpfCreateMapXattrRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		// All valid map names that should match
		{
			name:    "SysEnterInitTail",
			message: "libbpf: Error in bpf_create_map_xattr(sys_enter_init_tail)",
			matches: true,
		},
		{
			name:    "SysEnterSubmitTail",
			message: "libbpf: Error in bpf_create_map_xattr(sys_enter_submit_tail)",
			matches: true,
		},
		{
			name:    "SysEnterTails",
			message: "libbpf: Error in bpf_create_map_xattr(sys_enter_tails)",
			matches: true,
		},
		{
			name:    "SysExitInitTail",
			message: "libbpf: Error in bpf_create_map_xattr(sys_exit_init_tail)",
			matches: true,
		},
		{
			name:    "SysExitSubmitTail",
			message: "libbpf: Error in bpf_create_map_xattr(sys_exit_submit_tail)",
			matches: true,
		},
		{
			name:    "SysExitTails",
			message: "libbpf: Error in bpf_create_map_xattr(sys_exit_tails)",
			matches: true,
		},
		{
			name:    "ProgArray",
			message: "libbpf: Error in bpf_create_map_xattr(prog_array)",
			matches: true,
		},
		{
			name:    "ProgArrayTp",
			message: "libbpf: Error in bpf_create_map_xattr(prog_array_tp)",
			matches: true,
		},
		// Cases that should not match
		{
			name:    "NoMatch_DifferentMap",
			message: "libbpf: Error in bpf_create_map_xattr(other_map)",
			matches: false,
		},
		{
			name:    "NoMatch_DifferentFunction",
			message: "libbpf: Error in bpf_create_other_map(sys_enter_init_tail)",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: Error in bpf_create_map_xattr(sys_enter_init_tail) extra content",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: Error in bpf_create_map_xattr(sys_enter_init_tail)",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoBpfCreateMapXattrRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "BPF create map xattr regex should match expected result")
		})
	}
}

func Test_libbpfgoCreateUprobeRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		{
			name:    "Uprobe",
			message: "libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: No such file or directory",
			matches: true,
		},
		{
			name:    "Uretprobe",
			message: "libbpf: prog 'test_prog': failed to create uretprobe '/path/to/binary:0x2000' perf event: No such file or directory",
			matches: true,
		},
		{
			name:    "NoMatch_DifferentError",
			message: "libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: Permission denied",
			matches: false,
		},
		{
			name:    "NoMatch_DifferentProbeType",
			message: "libbpf: prog 'test_prog': failed to create kprobe '/path/to/binary:0x1000' perf event: No such file or directory",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: No such file or directory extra",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: prog 'test_prog': failed to create uprobe '/path/to/binary:0x1000' perf event: No such file or directory",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoCreateUprobeRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "Create uprobe regex should match expected result")
		})
	}
}

func Test_libbpfgoMissingLineInfoRegexp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
		matches bool
	}{
		{
			name:    "ExactMatch",
			message: "libbpf: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			matches: true,
		},
		{
			name:    "DifferentProgramName",
			message: "libbpf: prog 'another_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			matches: true,
		},
		{
			name:    "WithPrefix",
			message: "libbpf: some prefix prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			matches: true,
		},
		{
			name:    "NoMatch_DifferentMessage",
			message: "libbpf: prog 'test_program': some other BTF related message",
			matches: false,
		},
		{
			name:    "NoMatch_NotLibbpf",
			message: "other: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtEnd",
			message: "libbpf: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info. extra",
			matches: false,
		},
		{
			name:    "NoMatch_ExtraContentAtStart",
			message: "prefix libbpf: prog 'test_program': missing .BTF.ext line info for the main program, skipping all of .BTF.ext line info.",
			matches: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matches := libbpfgoMissingLineInfoRegexp.MatchString(tc.message)
			assert.Equal(t, tc.matches, matches, "Missing BTF line info regex should match expected result")
		})
	}
}
