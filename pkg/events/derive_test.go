package events_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
)

func deriveError(id events.ID, errMsg string) error {
	return fmt.Errorf("failed to derive event %d: %s", id, errMsg)
}

func Test_DeriveEvent(t *testing.T) {
	alwaysDeriveError := func() events.DeriveFunction {
		return func(e trace.Event) (trace.Event, bool, error) {
			return trace.Event{}, false, fmt.Errorf("derive error")
		}
	}
	mockDerivationTable := events.DerivationTable{
		events.Open: {
			events.Eventfd: {
				Enabled:  true,
				Function: alwaysDeriveError(),
			},
			events.EpollCreate: {
				Enabled: false,
				Function: func(e trace.Event) (trace.Event, bool, error) {
					return trace.Event{
						EventID: int(events.EpollCreate),
					}, true, nil
				},
			},
			events.Close: {
				Enabled: true,
				Function: func(e trace.Event) (trace.Event, bool, error) {
					return trace.Event{
						EventID: int(events.Close),
					}, true, nil
				},
			},
			events.CgroupMkdir: {
				Enabled: true,
				Function: func(e trace.Event) (trace.Event, bool, error) {
					return trace.Event{}, false, nil
				},
			},
		},
	}

	testCases := []struct {
		name            string
		event           trace.Event
		expectedDerived []trace.Event
		expectedErrors  []error
	}{
		{
			name: "derive open check for all cases",
			event: trace.Event{
				EventID: int(events.Open),
			},
			expectedDerived: []trace.Event{
				{
					EventID: int(events.Close),
				},
			},
			expectedErrors: []error{deriveError(events.Eventfd, "derive error")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			derived, errors := events.Derive(tc.event, mockDerivationTable)
			assert.Equal(t, tc.expectedDerived, derived)
			assert.Equal(t, tc.expectedErrors, errors)
		})
	}

}
