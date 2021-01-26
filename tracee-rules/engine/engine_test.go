package engine

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tracee-rules/signatures"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/require"
)

func TestEngine_consumeSource(t *testing.T) {
	inputs := EventSources{}
	inputs.Tracee = make(chan types.Event, 1)
	outputChan := make(chan types.Finding, 1)
	done := make(chan bool, 1)

	// gather all sigs
	sigs, err := signatures.GetSignatures(filepath.Join("../dist/rules"), nil)
	require.NoError(t, err)
	e := NewEngine(sigs, inputs, outputChan, nil)

	go func() {
		e.Start(done)
	}()

	// send a test event
	e.inputs.Tracee <- types.TraceeEvent{
		EventName:       "test_event",
		ProcessID:       2,
		ParentProcessID: 1,
		Args: []types.TraceeEventArgument{{
			Name: "test_yo",
		}},
	}

	// assert
	for _, s := range e.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: "*"}] {
		gotEvent := (<-e.signatures[s]).(types.TraceeEvent)
		if gotEvent.EventName == "test_event" {
			assert.Equal(t, []types.TraceeEventArgument{
				{
					Name: "test_yo",
				},
			}, gotEvent.Args)
			break
		}
	}

	// signal the end
	done <- true

	// cleanup
	close(done)
	close(outputChan)
	close(inputs.Tracee)
}
