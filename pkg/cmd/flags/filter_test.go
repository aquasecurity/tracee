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
		expected    []events.ID
		expectedErr error
	}{
		{
			name: "happy path - random events",
			eventFilter: cliFilter{
				Equal: []string{"ptrace", "openat"},
			},
			expected: []events.ID{events.Ptrace, events.Openat},
		},
		{
			name: "happy path - sched_proc*",
			eventFilter: cliFilter{
				Equal: []string{"sched_proc*", "openat"},
			},
			expected: []events.ID{
				events.SchedProcessExec,
				events.SchedProcessExit,
				events.SchedProcessFork,
				events.Openat,
			},
		},
		{
			name: "happy path - sched_proc* with exclude",
			eventFilter: cliFilter{
				Equal:    []string{"sched_proc*", "openat"},
				NotEqual: []string{"sched_process_exec"},
			},
			expected: []events.ID{
				events.SchedProcessExit,
				events.SchedProcessFork,
				events.Openat,
			},
		},
		{
			name: "happy path - containers set",
			setFilter: cliFilter{
				Equal: []string{"containers"},
			},
			expected: []events.ID{events.ContainerCreate, events.ContainerRemove, events.ExistingContainer},
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
	// remove internal events since they shouldn't be accesible by users
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
				assert.ElementsMatch(t, res, tc.expected)
			}
		})
	}
}
