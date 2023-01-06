package engine

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type regoFakeSignature struct {
	getMetadata       func() (detect.SignatureMetadata, error)
	getSelectedEvents func() ([]detect.SignatureEventSelector, error)
	init              func(detect.SignatureHandler) error
	onEvent           func(protocol.Event) error
	onSignal          func(signal detect.Signal) error
}

func (fs regoFakeSignature) GetMetadata() (detect.SignatureMetadata, error) {
	if fs.getMetadata != nil {
		return fs.getMetadata()
	}

	return detect.SignatureMetadata{
		ID:   "TRC-FAKE",
		Name: "Fake Signature",
	}, nil
}

func (fs regoFakeSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	if fs.getSelectedEvents != nil {
		return fs.getSelectedEvents()
	}

	return []detect.SignatureEventSelector{}, nil
}

func (fs regoFakeSignature) Init(cb detect.SignatureHandler) error {
	if fs.init != nil {
		return fs.init(cb)
	}
	return nil
}

func (fs regoFakeSignature) OnEvent(event protocol.Event) error {
	if fs.onEvent != nil {
		return fs.onEvent(event)
	}
	return nil
}

func (fs regoFakeSignature) OnSignal(signal detect.Signal) error {
	if fs.onSignal != nil {
		return fs.onSignal(signal)
	}
	return nil
}
func (fs *regoFakeSignature) Close() {}

type fakeSignature struct {
	getMetadata       func() (detect.SignatureMetadata, error)
	getSelectedEvents func() ([]detect.SignatureEventSelector, error)
	init              func(detect.SignatureHandler) error
	onEvent           func(protocol.Event) error
	onSignal          func(signal detect.Signal) error
}

func (fs fakeSignature) GetMetadata() (detect.SignatureMetadata, error) {
	if fs.getMetadata != nil {
		return fs.getMetadata()
	}

	return detect.SignatureMetadata{
		ID:   "TRC-FAKE2",
		Name: "Another Fake Signature",
	}, nil
}

func (fs fakeSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	if fs.getSelectedEvents != nil {
		return fs.getSelectedEvents()
	}

	return []detect.SignatureEventSelector{}, nil
}

func (fs fakeSignature) Init(cb detect.SignatureHandler) error {
	if fs.init != nil {
		return fs.init(cb)
	}
	return nil
}

func (fs fakeSignature) OnEvent(event protocol.Event) error {
	if fs.onEvent != nil {
		return fs.onEvent(event)
	}
	return nil
}

func (fs fakeSignature) OnSignal(signal detect.Signal) error {
	if fs.onSignal != nil {
		return fs.onSignal(signal)
	}
	return nil
}
func (fs *fakeSignature) Close() {}

func TestEngine_ConsumeSources(t *testing.T) {
	testCases := []struct {
		name              string
		inputEvent        protocol.Event
		inputSignature    regoFakeSignature
		expectedNumEvents int
		expectedError     string
		expectedEvent     interface{}
		config            Config
	}{
		{
			name: "happy path - with one matching selector",
			inputEvent: trace.Event{
				EventName:       "test_event",
				ProcessID:       2,
				ParentProcessID: 1,
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
						},
						Value: "/proc/self/mem",
					},
				},
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "test_event",
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent: trace.Event{
				ProcessID: 2, ParentProcessID: 1, Args: []trace.Argument{{ArgMeta: trace.ArgMeta{Name: "pathname", Type: ""}, Value: "/proc/self/mem"}},
				EventName: "test_event",
			},
		},
		{
			name: "happy path - with no matching event selector",
			inputEvent: trace.Event{
				EventName: "execve",
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
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
			inputEvent: trace.Event{
				EventName: "execve",
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "*",
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent: trace.Event{
				EventName: "execve",
			},
		},
		{
			name:       "happy path - with all events selector, no name",
			inputEvent: trace.Event{EventName: "execve"}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Source: "tracee",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent:     trace.Event{EventName: "execve"},
		},
		{
			name: "happy path - with one matching selector including event origin from container",
			inputEvent: trace.Event{
				EventName:       "test_event",
				ProcessID:       2,
				HostProcessID:   1002,
				ParentProcessID: 1,
				ContainerID:     "container ID",
				ContextFlags:    trace.ContextFlags{ContainerStarted: true},
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
						},
						Value: "/proc/self/mem",
					},
				},
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "test_event",
							Source: "tracee",
							Origin: "container",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent: trace.Event{
				ProcessID: 2, ParentProcessID: 1, HostProcessID: 1002, ContainerID: "container ID", ContextFlags: trace.ContextFlags{ContainerStarted: true}, Args: []trace.Argument{{ArgMeta: trace.ArgMeta{Name: "pathname", Type: ""}, Value: "/proc/self/mem"}},
				EventName: "test_event",
			},
		},
		{
			name: "happy path - with one matching selector with mismatching event origin from container",
			inputEvent: trace.Event{
				EventName:       "test_event",
				ProcessID:       2,
				HostProcessID:   1002,
				ParentProcessID: 1,
				ContainerID:     "container ID",
				ContextFlags:    trace.ContextFlags{ContainerStarted: true},
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
						},
						Value: "/proc/self/mem",
					},
				},
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "test_event",
							Source: "tracee",
							Origin: "host",
						},
					}, nil
				},
			},
			expectedNumEvents: 0,
		},
		{
			name: "happy path - with one matching selector including event origin from host",
			inputEvent: trace.Event{
				EventName:       "test_event",
				ProcessID:       2,
				HostProcessID:   2,
				ParentProcessID: 2,
				ContextFlags:    trace.ContextFlags{ContainerStarted: false},
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "pathname",
						},
						Value: "/proc/self/mem",
					},
				},
			}.ToProtocol(),
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "test_event",
							Source: "tracee",
							Origin: "host",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent: trace.Event{
				ProcessID: 2, ParentProcessID: 2, HostProcessID: 2, Args: []trace.Argument{{ArgMeta: trace.ArgMeta{Name: "pathname", Type: ""}, Value: "/proc/self/mem"}},
				EventName: "test_event",
			},
		},
		{
			name: "sad path - with all events selector, no source",
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name: "*",
						},
					}, nil
				},
			},
			expectedError: "signature Fake Signature doesn't declare an input source",
		},
		{
			name: "sad path - signature init fails",
			inputSignature: regoFakeSignature{
				init: func(handler detect.SignatureHandler) error {
					return errors.New("init failed")
				},
			},
			expectedNumEvents: 0,
			expectedError:     "error initializing signature Fake Signature: init failed",
		},
		{
			name: "sad path - getSelectedEvents returns an error",
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return nil, errors.New("getSelectedEvents error")
				},
			},
			expectedError: "error getting selected events for signature Fake Signature: getSelectedEvents error",
		},
		{
			name: "sad path - getMetadata returns an error",
			inputSignature: regoFakeSignature{
				getMetadata: func() (detect.SignatureMetadata, error) {
					return detect.SignatureMetadata{}, errors.New("getMetadata error")
				},
			},
			expectedError: "error getting metadata: getMetadata error",
		},
		{
			name: "happy path - signature receives a non tracee event",
			inputEvent: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Name:   "happy_event",
						Origin: "foo",
						Source: "system",
					},
				},
				Payload: "a great payload",
			},
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "happy_event",
							Source: "system",
							Origin: "foo",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent:     "a great payload",
		},
		{
			name: "happy path - signature with partial selector and non tracee source",
			inputEvent: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Name:   "foobar",
						Source: "system",
					},
				},
				Payload: "a great payload",
			},
			inputSignature: regoFakeSignature{
				getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name:   "foobar",
							Source: "system",
						},
					}, nil
				},
			},
			expectedNumEvents: 1,
			expectedEvent:     "a great payload",
		},
	}

	emptyEvent := protocol.Event{}

	for _, tc := range testCases {
		inputs := EventSources{}
		inputs.Tracee = make(chan protocol.Event, 1)
		outputChan := make(chan detect.Finding, 1)
		ctx, cancel := context.WithCancel(context.Background())
		var logBuf []byte
		loggerBuf := bytes.NewBuffer(logBuf)
		if !logger.IsSetFromEnv() {
			logger.Init(
				&logger.LoggerConfig{
					Writer:    loggerBuf,
					Level:     logger.InfoLevel,
					Encoder:   logger.NewJSONEncoder(logger.NewProductionConfig().EncoderConfig),
					Aggregate: false,
				},
			)
		}

		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				// signal the end
				cancel()

				// cleanup
				close(outputChan)
				close(inputs.Tracee)
			}()

			var sigs []detect.Signature
			sigs = append(sigs, &tc.inputSignature)

			// FIXME We should use another Go concurrency pattern to make this test logically correct.
			//       The gotNumEvents variable is causing data race, because it's accessed
			//       by two goroutines. Temporary workaround is to change from int to uint32 and
			//       use atomic.AddUint32 and atomic.LoadUint32 methods.
			//       go test -v -run=TestConsumeSources -race ./pkg/rules/engine/...
			var gotNumEvents uint32
			tc.inputSignature.onEvent = func(event protocol.Event) error {
				assert.Equal(t, tc.expectedEvent, event.Payload, tc.name)
				atomic.AddUint32(&gotNumEvents, 1)
				return nil
			}

			tc.config.Signatures = sigs

			e, err := NewEngine(tc.config, inputs, outputChan)
			require.NoError(t, err, "constructing engine")
			go func() {
				e.Start(ctx)
			}()

			// send a test event
			e.inputs.Tracee <- tc.inputEvent

			// assert
			var gotEvent protocol.Event
			time.Sleep(time.Millisecond * 1) // wait for events to propagate

			eventsCount := int(atomic.LoadUint32(&gotNumEvents))
			if tc.expectedNumEvents <= 0 {
				assert.Equal(t, emptyEvent, gotEvent, tc.name)
				assert.Zero(t, eventsCount, tc.name)
			} else {
				assert.Equal(t, tc.expectedNumEvents, eventsCount, tc.name)
			}

			if tc.expectedError != "" {
				assert.Contains(t, loggerBuf.String(), tc.expectedError, tc.name)
			}
		})
	}
}

func TestEngine_GetSelectedEvents(t *testing.T) {
	sigs := []detect.Signature{
		&regoFakeSignature{
			getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
				return []detect.SignatureEventSelector{
					{
						Name:   "test_event",
						Source: "tracee",
					},
					{
						Name:   "test_event2",
						Source: "tracee",
					},
				}, nil
			},
		},
		&regoFakeSignature{
			getSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
				return []detect.SignatureEventSelector{
					{
						Name:   "test_event",
						Source: "tracee",
						Origin: "host",
					},
					{
						Name:   "test_event2",
						Source: "tracee",
					},
				}, nil
			},
		},
	}

	config := Config{Signatures: sigs}
	e, err := NewEngine(config, EventSources{Tracee: make(chan protocol.Event)}, make(chan detect.Finding))
	require.NoError(t, err, "constructing engine")
	se := e.GetSelectedEvents()
	expected := []detect.SignatureEventSelector{
		{
			Name:   "test_event",
			Source: "tracee",
			Origin: "*",
		},
		{
			Name:   "test_event2",
			Source: "tracee",
			Origin: "*",
		},
		{
			Name:   "test_event",
			Source: "tracee",
			Origin: "host",
		},
	}
	assert.ElementsMatch(t, expected, se)
}

func TestEngine_LoadSignature(t *testing.T) {
	testCases := []struct {
		name          string
		signatures    []detect.Signature
		expectedCount int
	}{
		{
			name:          "load one signature",
			signatures:    []detect.Signature{&regoFakeSignature{}},
			expectedCount: 1,
		},
		{
			name:          "load two signatures",
			signatures:    []detect.Signature{&regoFakeSignature{}, &fakeSignature{}},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := make(chan protocol.Event)
			source := EventSources{
				Tracee: input,
			}
			output := make(chan detect.Finding)
			engine, err := NewEngine(Config{}, source, output)
			require.NoError(t, err)

			for _, sig := range tc.signatures {
				metadata, err := sig.GetMetadata()
				require.NoError(t, err)

				id, err := engine.LoadSignature(sig)
				assert.NoError(t, err)
				assert.Equal(t, metadata.ID, id)
			}

			//check that signature stats were correctly incremented
			assert.Equal(t, tc.expectedCount, int(engine.Stats().Signatures.Read()))
			close(input)
		})
	}

}
