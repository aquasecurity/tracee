package events_test

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"testing"

	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
)

func deriveError(id events.ID, errMsg string) error {
	return fmt.Errorf("failed to derive event %d: %s", id, errMsg)
}

func Test_DeriveEvent(t *testing.T) {
	testEventID := events.ID(1)
	failEventID := events.ID(11)
	deriveEventID := events.ID(12)
	noDerivationEventID := events.ID(13)
	alwaysDeriveError := func() events.DeriveFunction {
		return func(e trace.Event) ([]trace.Event, []error) {
			return []trace.Event{}, []error{fmt.Errorf("derive error")}
		}
	}
	mockDerivationTable := events.DerivationTable{
		testEventID: {
			failEventID: {
				Function: alwaysDeriveError(),
				Enabled:  true,
			},
			deriveEventID: {
				Function: func(e trace.Event) ([]trace.Event, []error) {
					return []trace.Event{
						{
							EventID: int(deriveEventID),
						},
					}, nil
				},
				Enabled: true,
			},
			noDerivationEventID: {
				Function: func(e trace.Event) ([]trace.Event, []error) {
					return []trace.Event{}, nil
				},
				Enabled: true,
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
			name: "derive test event check for all cases",
			event: trace.Event{
				EventID: int(testEventID),
			},
			expectedDerived: []trace.Event{
				{
					EventID: int(deriveEventID),
				},
			},
			expectedErrors: []error{deriveError(failEventID, "derive error")},
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
