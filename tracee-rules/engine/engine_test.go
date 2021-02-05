package engine

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
	"github.com/stretchr/testify/assert"
)

type fakeSignature struct {
	getMetadata       func() (types.SignatureMetadata, error)
	getSelectedEvents func() ([]types.SignatureEventSelector, error)
	init              func(types.SignatureHandler) error
	onEvent           func(types.Event) error
	onSignal          func(signal types.Signal) error
}

func (fs fakeSignature) GetMetadata() (types.SignatureMetadata, error) {
	if fs.getMetadata != nil {
		return fs.getMetadata()
	}

	return types.SignatureMetadata{
		Name: "Fake Signature",
	}, nil
}

func (fs fakeSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	if fs.getSelectedEvents != nil {
		return fs.getSelectedEvents()
	}

	return []types.SignatureEventSelector{}, nil
}

func (fs fakeSignature) Init(cb types.SignatureHandler) error {
	if fs.init != nil {
		return fs.init(cb)
	}
	return nil
}

func (fs fakeSignature) OnEvent(event types.Event) error {
	if fs.onEvent != nil {
		return fs.onEvent(event)
	}
	return nil
}

func (fs fakeSignature) OnSignal(signal types.Signal) error {
	if fs.onSignal != nil {
		return fs.onSignal(signal)
	}
	return nil
}

func TestConsumeSources(t *testing.T) {
	testCases := []struct {
		name              string
		inputEvent        tracee.Event
		inputSignature    fakeSignature
		expectedNumEvents int
		expectedError     string
	}{
		{
			name: "happy path - with one matching selector",
			inputEvent: tracee.Event{
				EventName:       "test_event",
				ProcessID:       2,
				ParentProcessID: 1,
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "pathname",
						},
						Value: "/proc/self/mem",
					},
				},
			},
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return []types.SignatureEventSelector{
						{
							Name:   "test_event",
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
		},
		{
			name: "happy path - with no matching event selector",
			inputEvent: tracee.Event{
				EventName: "execve",
			},
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return []types.SignatureEventSelector{
						{
							Name:   "not execve",
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 0,
		},
		{
			name: "happy path - with all events selector",
			inputEvent: tracee.Event{
				EventName: "execve",
			},
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return []types.SignatureEventSelector{
						{
							Name:   "*",
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
		},
		{
			name: "happy path - with all events selector, no name",
			inputEvent: tracee.Event{
				EventName: "execve",
			},
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return []types.SignatureEventSelector{
						{
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
		},
		{
			name: "sad path - with all events selector, no source",
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return []types.SignatureEventSelector{
						{
							Name: "*",
						},
					}, nil
				},
			},
			expectedError: "signature Fake Signature doesn't declare an input source\n",
		},
		{
			name: "sad path - signature init fails",
			inputSignature: fakeSignature{
				init: func(handler types.SignatureHandler) error {
					return errors.New("init failed")
				},
			},
			expectedNumEvents: 0,
			expectedError:     "error initializing signature Fake Signature: init failed\n",
		},
		{
			name: "sad path - getSelectedEvents returns an error",
			inputSignature: fakeSignature{
				getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
					return nil, errors.New("getSelectedEvents error")
				},
			},
			expectedError: "error getting selected events for signature Fake Signature: getSelectedEvents error\n",
		},
		{
			name: "sad path - getMetadata returns an error",
			inputSignature: fakeSignature{
				getMetadata: func() (types.SignatureMetadata, error) {
					return types.SignatureMetadata{}, errors.New("getMetadata error")
				},
			},
			expectedError: "error getting metadata: getMetadata error\n",
		},
	}

	for _, tc := range testCases {
		inputs := EventSources{}
		inputs.Tracee = make(chan types.Event, 1)
		outputChan := make(chan types.Finding, 1)
		done := make(chan bool, 1)
		var logBuf []byte
		logger := bytes.NewBuffer(logBuf)

		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				// signal the end
				done <- true

				// cleanup
				close(done)
				close(outputChan)
				close(inputs.Tracee)
			}()

			var sigs []types.Signature
			sigs = append(sigs, &tc.inputSignature)

			var gotNumEvents int
			tc.inputSignature.onEvent = func(event types.Event) error {
				assert.Equal(t, tc.inputEvent, event, tc.name)
				gotNumEvents++
				return nil
			}

			e := NewEngine(sigs, inputs, outputChan, logger)
			go func() {
				e.Start(done)
			}()

			// send a test event
			e.inputs.Tracee <- tc.inputEvent

			// assert
			var gotEvent types.Event
			time.Sleep(time.Millisecond * 1) // wait for events to propagate

			if tc.expectedNumEvents <= 0 {
				assert.Nil(t, gotEvent, tc.name)
				assert.Zero(t, gotNumEvents, tc.name)
			} else {
				assert.Equal(t, tc.expectedNumEvents, gotNumEvents, tc.name)
			}

			if tc.expectedError != "" {
				assert.Contains(t, logger.String(), tc.expectedError, tc.name)
			}
		})
	}
}
