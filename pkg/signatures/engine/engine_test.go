package engine

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestEngine_ConsumeSources(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		inputEvent        protocol.Event
		inputSignature    *signature.FakeSignature
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
				Container:       trace.Container{ID: "container ID"},
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
				ProcessID: 2, ParentProcessID: 1, HostProcessID: 1002, Container: trace.Container{ID: "container ID"}, ContextFlags: trace.ContextFlags{ContainerStarted: true}, Args: []trace.Argument{{ArgMeta: trace.ArgMeta{Name: "pathname", Type: ""}, Value: "/proc/self/mem"}},
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
				Container:       trace.Container{ID: "container ID"},
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return []detect.SignatureEventSelector{
						{
							Name: "*",
						},
					}, nil
				},
			},
			expectedError: "Signature Fake Signature doesn't declare an input source",
		},
		{
			name: "sad path - signature init fails",
			inputSignature: &signature.FakeSignature{
				FakeInit: func(ctx detect.SignatureContext) error {
					return errors.New("init failed")
				},
			},
			expectedNumEvents: 0,
			expectedError:     "error initializing signature Fake Signature: init failed",
		},
		{
			name: "sad path - getSelectedEvents returns an error",
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
					return nil, errors.New("getSelectedEvents error")
				},
			},
			expectedError: "error getting selected events for signature Fake Signature: getSelectedEvents error",
		},
		{
			name: "sad path - getMetadata returns an error",
			inputSignature: &signature.FakeSignature{
				FakeGetMetadata: func() (detect.SignatureMetadata, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
			inputSignature: &signature.FakeSignature{
				FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			inputs := EventSources{}
			inputs.Tracee = make(chan protocol.Event, 1)
			outputChan := make(chan *detect.Finding, 1)

			defer func() {
				// signal the end
				cancel()

				// give some time for the goroutine to finish
				time.Sleep(1 * time.Second)

				// cleanup
				close(inputs.Tracee)
				close(outputChan)
			}()

			var logBuf []byte
			loggerBuf := bytes.NewBuffer(logBuf)
			logger.Init(
				logger.LoggingConfig{
					Logger: logger.NewLogger(logger.LoggerConfig{
						Writer:  loggerBuf,
						Level:   logger.NewAtomicLevelAt(logger.InfoLevel),
						Encoder: logger.NewJSONEncoder(logger.NewProductionConfig().EncoderConfig),
					}),
					Aggregate: false,
				},
			)

			var sigs []detect.Signature
			sigs = append(sigs, tc.inputSignature)

			// FIXME We should use another Go concurrency pattern to make this test logically correct.
			//       The gotNumEvents variable is causing data race, because it's accessed
			//       by two goroutines. Temporary workaround is to change from int to uint32 and
			//       use atomic.AddUint32 and atomic.LoadUint32 methods.
			//       go test -v -run=TestConsumeSources -race ./pkg/signatures/engine/...
			var gotNumEvents uint32
			tc.inputSignature.FakeOnEvent = func(event protocol.Event) error {
				assert.Equal(t, tc.expectedEvent, event.Payload, tc.name)
				atomic.AddUint32(&gotNumEvents, 1)
				return nil
			}

			tc.config.Signatures = sigs

			e, err := NewEngine(tc.config, inputs, outputChan)
			require.NoError(t, err, "constructing engine")

			err = e.Init()
			require.NoError(t, err, "initializing engine")

			go e.Start(ctx)

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
	t.Parallel()

	sigs := []detect.Signature{
		&signature.FakeSignature{
			FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
		&signature.FakeSignature{
			FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
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
	e, err := NewEngine(config, EventSources{Tracee: make(chan protocol.Event)}, make(chan *detect.Finding))
	require.NoError(t, err, "constructing engine")

	err = e.Init()
	require.NoError(t, err, "initializing engine")

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
	t.Parallel()

	testCases := []struct {
		name          string
		signatures    []detect.Signature
		expectedCount int
	}{
		{
			name:          "load one signature",
			signatures:    []detect.Signature{&signature.FakeSignature{}},
			expectedCount: 1,
		},
		{
			name:          "load two signatures",
			signatures:    []detect.Signature{&signature.FakeSignature{}, &signature.FakeSignature{}},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := make(chan protocol.Event)
			source := EventSources{
				Tracee: input,
			}
			output := make(chan *detect.Finding)
			engine, err := NewEngine(Config{}, source, output)
			require.NoError(t, err)

			for _, sig := range tc.signatures {
				metadata, err := sig.GetMetadata()
				require.NoError(t, err)

				id, err := engine.LoadSignature(sig)
				assert.NoError(t, err)
				assert.Equal(t, metadata.ID, id)
			}

			// check that signature stats were correctly incremented
			assert.Equal(t, tc.expectedCount, int(engine.Stats().Signatures.Get()))
			close(input)
		})
	}
}
