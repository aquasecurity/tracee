package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestFilter_prepareEventsToTrace(t *testing.T) {
	testCases := []struct {
		name        string
		eventFilter cliFilter
		setFilter   cliFilter
		expected    map[events.ID]string
		expectedErr error
	}{
		{
			name: "happy path - random events",
			eventFilter: cliFilter{
				Equal: []string{"ptrace", "openat"},
			},
			expected: map[events.ID]string{
				events.Ptrace: "ptrace",
				events.Openat: "openat",
			},
		},
		{
			name: "happy path - sched_proc*",
			eventFilter: cliFilter{
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
			eventFilter: cliFilter{
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
			name: "happy path - containers set",
			setFilter: cliFilter{
				Equal: []string{"containers"},
			},
			expected: map[events.ID]string{
				events.ContainerCreate:   "container_create",
				events.ContainerRemove:   "container_remove",
				events.ExistingContainer: "existing_container",
			},
		},
		{
			name: "sad path - event doesn't exist",
			eventFilter: cliFilter{
				Equal: []string{"blah"},
			},
			expectedErr: InvalidEventError("blah"),
		},
		{
			name: "sad path - no event with prefix",
			eventFilter: cliFilter{
				Equal: []string{"blah*"},
			},
			expectedErr: InvalidEventError("blah*"),
		},
		{
			name: "sad path - no event with suffix",
			eventFilter: cliFilter{
				Equal: []string{"*blah"},
			},
			expectedErr: InvalidEventError("*blah"),
		},
		{
			name: "sad path - set doesn't exist",
			setFilter: cliFilter{
				Equal: []string{"blah"},
			},
			expectedErr: InvalidSetError("blah"),
		},
	}
	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accessible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := prepareEventsToTrace(tc.eventFilter, tc.setFilter, eventsNameToID)
			if tc.expectedErr != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, res)
			}
		})
	}
}
