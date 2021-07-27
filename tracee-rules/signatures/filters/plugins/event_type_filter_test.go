package plugins

import (
	"fmt"
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
		matchingSigIDs  []uint32
	}{
		{
			name:            "Create EventSelectorFilter with no signatures",
			inputSignatures: []fakeSignature{{}},
			matchingSigIDs:  []uint32{},
		},
		{
			name: "Create EventSelectorFilter with one signature which matches the given event",
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
			matchingSigIDs: []uint32{0},
		},
		{
			name: "Create EventSelectorFilter with one signature which does not match the given event",
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
			matchingSigIDs: []uint32{},
		},
		{
			name: "Create EventSelectorFilter with one signature which matches all events",
			inputSignatures: []fakeSignature{
				{
					getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
						return []types.SignatureEventSelector{
							{
								Name:   "*",
								Source: "tracee",
							},
						}, nil
					},
				},
			},
			matchingSigIDs: []uint32{0},
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
		eventFilter, createFilterError := CreateEventsSelectorFilter(inputSignatures, &logger)
		require.NoError(t, createFilterError, "creating EventSelectorFilter")
		filteredSignaturesBitmap, filterError := eventFilter.FilterByEvent(event)
		require.NoError(t, filterError, "get filtered events for example one")
		assert.Equal(t, testCase.matchingSigIDs, filteredSignaturesBitmap.ToArray(), testCase.name)
	}
}

func TestAddSignature(t *testing.T) {
	sig := fakeSignature{
		getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
			return []types.SignatureEventSelector{
				{
					Name:   "test_event",
					Source: "tracee",
				},
			}, nil
		},
	}
	logger := *log.New(os.Stdout, "", 0)
	eventFilter, createFilterError := CreateEventsSelectorFilter([]types.Signature{}, &logger)
	require.NoError(t, createFilterError, "creating EventSelectorFilter")
	sigID := 0
	addSignatureError := eventFilter.AddSignature(sig, uint32(sigID))
	require.NoError(t, addSignatureError, "add first signature to filter")
	secondAddSignatureError := eventFilter.AddSignature(sig, uint32(sigID))
	sigMeta, _ := sig.GetMetadata()
	errMsg := fmt.Sprintf("error registering signature %s to EventSelectorFilter: given signature signatureID (%d) is already taken", sigMeta.Name, sigID)
	require.Errorf(t, secondAddSignatureError, errMsg)
}

func TestRemoveSignature(t *testing.T) {
	sig := fakeSignature{
		getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
			return []types.SignatureEventSelector{
				{
					Name:   "test_event",
					Source: "tracee",
				},
			}, nil
		},
	}
	logger := *log.New(os.Stdout, "", 0)
	eventFilter, createFilterError := CreateEventsSelectorFilter([]types.Signature{sig}, &logger)
	require.NoError(t, createFilterError, "creating EventSelectorFilter")
	sigID := 0
	removeError := eventFilter.RemoveSignature(uint32(sigID))
	require.NoError(t, removeError, "removed legitimate signature")
	secondRemoveError := eventFilter.RemoveSignature(uint32(sigID))
	errMsg := fmt.Sprintf("error removing signature with signatureID %d: no matching signature's signatureID exist", sigID)
	require.Errorf(t, secondRemoveError, errMsg)
}
