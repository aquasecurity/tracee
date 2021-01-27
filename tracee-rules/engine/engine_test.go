package engine

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestEngine_consumeSource(t *testing.T) {
	testCases := []struct {
		name         string
		inputEvent   types.TraceeEvent
		expectedArgs []types.TraceeEventArgument
	}{
		{
			name: "happy path - with no matching filter",
			inputEvent: types.TraceeEvent{
				EventName:       "test_event",
				ProcessID:       2,
				ParentProcessID: 1,
				Args: []types.TraceeEventArgument{{
					Name: "test_foo",
				}},
			},
			expectedArgs: []types.TraceeEventArgument{
				{
					Name: "test_foo",
				},
			},
		},
		{
			name: "happy path - with matching filter on EventName",
			inputEvent: types.TraceeEvent{
				EventName:       "execve",
				ProcessID:       2,
				ParentProcessID: 1,
				Args: []types.TraceeEventArgument{{
					Name: "foobarbaz",
				}},
			},
			expectedArgs: []types.TraceeEventArgument{
				{
					Name: "foobarbaz",
				},
			},
		},
	}

	for _, tc := range testCases {
		inputs := EventSources{}
		inputs.Tracee = make(chan types.Event, 1)
		outputChan := make(chan types.Finding, 1)
		done := make(chan bool, 1)
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				// signal the end
				done <- true

				// cleanup
				close(done)
				close(outputChan)
				close(inputs.Tracee)
			}()

			// gather all sigs
			sigs, err := signatures.GetSignatures(filepath.Join("../dist/rules"), nil)
			require.NoError(t, err, tc.name)
			require.NotEmpty(t, sigs, tc.name)
			e := NewEngine(sigs, inputs, outputChan, nil)

			go func() {
				e.Start(done)
			}()

			// send a test event
			e.inputs.Tracee <- tc.inputEvent

			// assert
			for _, s := range e.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: "*"}] {
				gotEvent := (<-e.signatures[s]).(types.TraceeEvent)
				if gotEvent.EventName == tc.inputEvent.EventName {
					assert.Equal(t, tc.expectedArgs, gotEvent.Args, tc.name)
					return
				}
			}

			for _, s := range e.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: tc.inputEvent.EventName}] {
				gotEvent := (<-e.signatures[s]).(types.TraceeEvent)
				if gotEvent.EventName == tc.inputEvent.EventName {
					assert.Equal(t, tc.expectedArgs, gotEvent.Args, tc.name)
					return
				}
			}
		})
	}
}
