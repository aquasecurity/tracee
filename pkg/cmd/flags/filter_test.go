package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestFilter_prepareEventsToTrace(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		eventFilter eventFilter
		expected    map[events.ID]string
		expectedErr error
	}{
		{
			name: "happy path - random events",
			eventFilter: eventFilter{
				Equal: []string{"ptrace", "openat"},
			},
			expected: map[events.ID]string{
				events.Ptrace: "ptrace",
				events.Openat: "openat",
			},
		},
		{
			name: "happy path - sched_proc*",
			eventFilter: eventFilter{
				Equal: []string{"sched_proc*", "openat"},
			},
			expected: map[events.ID]string{
				events.SchedProcessExec: "sched_process_exec",
				events.SchedProcessExit: "sched_process_exit",
				events.SchedProcessFork: "sched_process_fork",
				events.Openat:           "openat",
			},
		},
		{
			name: "happy path - sched_proc* with exclude",
			eventFilter: eventFilter{
				Equal:    []string{"sched_proc*", "openat"},
				NotEqual: []string{"sched_process_exec"},
			},
			expected: map[events.ID]string{
				events.SchedProcessExit: "sched_process_exit",
				events.SchedProcessFork: "sched_process_fork",
				events.Openat:           "openat",
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
	eventsNameToID := events.Core.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		if events.Core.GetDefinitionByID(id).IsInternal() {
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
