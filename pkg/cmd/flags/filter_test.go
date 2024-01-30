package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/extensions"
)

func TestFilter_prepareEventsToTrace(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		eventFilter eventFilter
		expected    map[int]string
		expectedErr error
	}{
		{
			name: "happy path - random events",
			eventFilter: eventFilter{
				Equal: []string{"ptrace", "openat"},
			},
			expected: map[int]string{
				extensions.Ptrace: "ptrace",
				extensions.Openat: "openat",
			},
		},
		{
			name: "happy path - sched_proc*",
			eventFilter: eventFilter{
				Equal: []string{"sched_proc*", "openat"},
			},
			expected: map[int]string{
				extensions.SchedProcessExec: "sched_process_exec",
				extensions.SchedProcessExit: "sched_process_exit",
				extensions.SchedProcessFork: "sched_process_fork",
				extensions.Openat:           "openat",
			},
		},
		{
			name: "happy path - sched_proc* with exclude",
			eventFilter: eventFilter{
				Equal:    []string{"sched_proc*", "openat"},
				NotEqual: []string{"sched_process_exec"},
			},
			expected: map[int]string{
				extensions.SchedProcessExit: "sched_process_exit",
				extensions.SchedProcessFork: "sched_process_fork",
				extensions.Openat:           "openat",
			},
		},
		{
			name: "sad path - event doesn't exist",
			eventFilter: eventFilter{
				Equal: []string{"blah"},
			},
			expectedErr: InvalidEventError("blah"),
		},
		{
			name: "sad path - no event with prefix",
			eventFilter: eventFilter{
				Equal: []string{"blah*"},
			},
			expectedErr: InvalidEventError("blah*"),
		},
		{
			name: "sad path - no event with suffix",
			eventFilter: eventFilter{
				Equal: []string{"*blah"},
			},
			expectedErr: InvalidEventError("*blah"),
		},
	}
	eventsNameToID := extensions.Definitions.NamesToIDsFromAllExts()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		if extensions.Definitions.GetByIDFromAny(id).IsInternal() {
			delete(eventsNameToID, event)
		}
	}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := prepareEventsToTrace(tc.eventFilter, eventsNameToID)
			if tc.expectedErr != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, res)
			}
		})
	}
}
