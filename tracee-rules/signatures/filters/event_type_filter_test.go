package filter

import (
	"log"
	"os"
	"testing"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSignature struct {
	getMetadata       func() (types.SignatureMetadata, error)
	getSelectedEvents func() ([]types.SignatureEventSelector, error)
	init              func(types.SignatureHandler) error
	onEvent           func(types.Event) error
	onSignal          func(signal types.Signal) error
	close             func()
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
func (fs fakeSignature) Close() {}

func TestCreateEventFilter(t *testing.T) {
	testCases := []struct {
		name            string
		inputSignatures []fakeSignature
		expectedError   string
		matchingUIDs    []uint32
	}{
		{
			name: "Create EventTypeFilter with no signatures",
			inputSignatures: []fakeSignature{
				{
					getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
						return []types.SignatureEventSelector{
							{
								Name:   "not_matching_type",
								Source: "tracee",
							},
						}, nil
					},
				},
			},
			matchingUIDs: []uint32{},
		},
		{
			name: "Create EventTypeFilter with one signature matching the given event",
			inputSignatures: []fakeSignature{
				{
					getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
						return []types.SignatureEventSelector{
							{
								Name:   "test_event",
								Source: "tracee",
							},
						}, nil
					},
				},
			},
			matchingUIDs: []uint32{0},
		},
		{
			name: "Create EventTypeFilter with one signature not matching the given event",
			inputSignatures: []fakeSignature{
				{
					getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
						return []types.SignatureEventSelector{
							{
								Name:   "not_matching_type",
								Source: "tracee",
							},
						}, nil
					},
				},
			},
			matchingUIDs: []uint32{},
		},
		{
			name: "Create EventTypeFilter with one signature matching all events",
			inputSignatures: []fakeSignature{
				{
					getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
						return []types.SignatureEventSelector{
							{
								Name:   "not_matching_type",
								Source: "tracee",
							},
						}, nil
					},
				},
			},
			matchingUIDs: []uint32{0},
		},
	}
	event := tracee.Event{
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
	}
	logger := *log.New(os.Stdout, "", 0)

	for _, testCase := range testCases {
		var inputSignatures []types.Signature
		for _, signature := range testCase.inputSignatures {
			inputSignatures = append(inputSignatures, signature)
		}
		eventFilter, err := CreateEventFilter(inputSignatures, &logger)
		require.NoError(t, err, "creating EventTypeFilter")
		filteredSignaturesBitmap, err := eventFilter.FilterByEvent(event)
		require.NoError(t, err, "get filtered events for example one")
		assert.NotEqual(t, testCase.matchingUIDs, filteredSignaturesBitmap.ToArray(), testCase.name)
	}
}
