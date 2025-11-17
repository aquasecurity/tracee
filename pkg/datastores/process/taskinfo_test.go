package process

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/common/tests"
)

// TestTaskInfoFeed_PrintSizes prints the sizes of the structs used in the TaskInfoFeed type.
// Run it as DEBUG test to see the output.
func TestTaskInfoFeed_PrintSizes(t *testing.T) {
	taskInfo := TaskInfoFeed{}
	tests.PrintStructSizes(t, os.Stdout, taskInfo)
}

// TestTaskInfoFeed_ShouldSkipProcfsUpdate tests the validation function that determines
// whether procfs enrichment should be skipped because we already have complete BPF data.
func TestTaskInfoFeed_ShouldSkipProcfsUpdate(t *testing.T) {
	tt := []struct {
		name     string
		feed     TaskInfoFeed
		expected bool
	}{
		{
			name: "complete_data_all_fields_set",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: true,
		},
		{
			name: "empty_feed_all_zeros",
			feed: TaskInfoFeed{
				Name:   "",
				Tid:    0,
				Pid:    0,
				PPid:   0,
				NsTid:  0,
				NsPid:  0,
				NsPPid: 0,
			},
			expected: false,
		},
		{
			name: "missing_name_only",
			feed: TaskInfoFeed{
				Name:   "",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "missing_tid_only",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    0,
				Pid:    1234,
				PPid:   1,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "missing_pid_only",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    0,
				PPid:   1,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "missing_ppid_only",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   0,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "missing_nstid_only",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  0,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "missing_nspid_only",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  5678,
				NsPid:  0,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "namespace_pids_not_set_marked_as_minus_one",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  -1,
				NsPid:  -1,
				NsPPid: -1,
			},
			expected: false, // -1 means "not set/not available", not complete
		},
		{
			name: "partial_data_only_host_pids",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    1234,
				Pid:    1234,
				PPid:   1,
				NsTid:  0,
				NsPid:  0,
				NsPPid: 0,
			},
			expected: false,
		},
		{
			name: "partial_data_only_namespace_pids",
			feed: TaskInfoFeed{
				Name:   "test-process",
				Tid:    0,
				Pid:    0,
				PPid:   0,
				NsTid:  5678,
				NsPid:  5678,
				NsPPid: 1,
			},
			expected: false,
		},
		{
			name: "init_process_complete",
			feed: TaskInfoFeed{
				Name:   "systemd",
				Tid:    1,
				Pid:    1,
				PPid:   0, // init has no parent, but we check PPid != 0
				NsTid:  1,
				NsPid:  1,
				NsPPid: 0,
			},
			expected: false, // init process with PPid=0 is not considered complete by this check
		},
		{
			name: "mutable_fields_not_checked_uid_gid",
			feed: TaskInfoFeed{
				Name:        "test-process",
				Tid:         1234,
				Pid:         1234,
				PPid:        1,
				NsTid:       5678,
				NsPid:       5678,
				NsPPid:      1,
				Uid:         0, // mutable, not checked
				Gid:         0, // mutable, not checked
				StartTimeNS: 0, // immutable but not checked
				ExitTimeNS:  0, // immutable but not checked
			},
			expected: true, // mutable/timing fields don't affect completeness
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.feed.ShouldSkipProcfsUpdate()
			assert.Equal(t, tc.expected, result,
				"ShouldSkipProcfsUpdate() = %v, expected %v for feed: %+v",
				result, tc.expected, tc.feed)
		})
	}
}
