package filters

import (
	"log"
	"os"
	"testing"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type basicFakeSignature struct {
	metadata types.SignatureMetadata
	selector []types.SignatureEventSelector
}

func (fs basicFakeSignature) GetMetadata() (types.SignatureMetadata, error) {
	return fs.metadata, nil
}

func (fs basicFakeSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return fs.selector, nil
}

func (fs basicFakeSignature) Init(cb types.SignatureHandler) error {
	return nil
}

func (fs basicFakeSignature) OnEvent(event types.Event) error {
	return nil
}

func (fs basicFakeSignature) OnSignal(signal types.Signal) error {
	return nil
}
func (fs basicFakeSignature) Close() {}

var matchingSignature = basicFakeSignature{
	metadata: types.SignatureMetadata{
		Name: "Fake Signature",
	},
	selector: []types.SignatureEventSelector{
		{
			Name:   "test_event",
			Source: "tracee",
		},
	},
}
var notMatchingSignature = basicFakeSignature{
	metadata: types.SignatureMetadata{
		Name: "Fake Signature",
	},
	selector: []types.SignatureEventSelector{
		{
			Name:   "not_matching_type",
			Source: "tracee",
		},
	},
}

var allMatchingSignature = basicFakeSignature{
	metadata: types.SignatureMetadata{
		Name: "Fake Signature",
	},
	selector: []types.SignatureEventSelector{
		{
			Name:   "*",
			Source: "tracee",
		},
	},
}
var event = tracee.Event{
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

func TestNewFilterManager(t *testing.T) {
	testCases := []struct {
		name            string
		inputSignatures []basicFakeSignature
		expectedError   string
		matchingSigs    []basicFakeSignature
	}{
		{
			name:            "Create Manager with no signatures",
			inputSignatures: []basicFakeSignature{{}},
			matchingSigs:    []basicFakeSignature{},
		},
		{
			name:            "Create Manager with one signature which matches the given event",
			inputSignatures: []basicFakeSignature{matchingSignature},
			matchingSigs:    []basicFakeSignature{matchingSignature},
		},
		{
			name:            "Create Manager with one signature which does not match the given event",
			inputSignatures: []basicFakeSignature{notMatchingSignature},
			matchingSigs:    []basicFakeSignature{},
		},
		{
			name:            "Create Manager with one signature which matches all events",
			inputSignatures: []basicFakeSignature{allMatchingSignature},
			matchingSigs:    []basicFakeSignature{allMatchingSignature},
		},
		{
			name:            "Create Manager with one signature of each type - matching, not matching, all matching",
			inputSignatures: []basicFakeSignature{matchingSignature, notMatchingSignature, allMatchingSignature},
			matchingSigs:    []basicFakeSignature{matchingSignature, allMatchingSignature},
		},
	}
	logger := *log.New(os.Stdout, "", 0)

	for _, testCase := range testCases {
		inputSignatures := []types.Signature{}
		for _, signature := range testCase.inputSignatures {
			inputSignatures = append(inputSignatures, signature)
		}
		expectedResultSignatures := []types.Signature{}
		for _, signature := range testCase.matchingSigs {
			expectedResultSignatures = append(expectedResultSignatures, signature)
		}

		filterManager, err := NewFilterManager(&logger, inputSignatures)
		require.NoError(t, err, "creating Manager")
		filteredSignatures, err := filterManager.GetFilteredSignatures(event)
		require.NoError(t, err, "get filtered events for example one")
		assert.Equalf(t, expectedResultSignatures, filteredSignatures, testCase.name)
	}
}

func TestFilterManager_AddSignature(t *testing.T) {
	logger := *log.New(os.Stdout, "", 0)
	filterManager, err := NewFilterManager(&logger, []types.Signature{})
	require.NoError(t, err, "creating Manager")
	filteredSigs, err := filterManager.GetFilteredSignatures(event)
	require.NoError(t, err, "Getting matching signatures without registered signatures")
	require.EqualValues(t, []types.Signature{}, filteredSigs, "Getting matching signatures without registered signatures")
	err = filterManager.AddSignature(matchingSignature)
	require.NoError(t, err, "Adding new signature to the Manager")
	filteredSigs, err = filterManager.GetFilteredSignatures(event)
	assert.NoError(t, err, "Getting matching signatures with matching registered signature")
	assert.EqualValues(t, []types.Signature{matchingSignature}, filteredSigs, "Getting matching signatures with matching registered signature")
}

func TestFilterManager_RemoveSignature(t *testing.T) {
	logger := *log.New(os.Stdout, "", 0)
	filterManager, err := NewFilterManager(&logger, []types.Signature{matchingSignature})
	require.NoError(t, err, "creating Manager with a single signature")
	filteredSigs, err := filterManager.GetFilteredSignatures(event)
	require.NoError(t, err, "Getting matching signatures with matching registered signature")
	require.EqualValues(t, []types.Signature{matchingSignature}, filteredSigs, "Getting matching signatures with matching registered signature")
	err = filterManager.RemoveSignature(matchingSignature)
	require.NoError(t, err, "Removing the matching signature from the Manager")
	filteredSigs, err = filterManager.GetFilteredSignatures(event)
	assert.NoError(t, err, "Getting matching signatures without matching registered signature")
	assert.EqualValues(t, []types.Signature{}, filteredSigs, "Getting matching signatures without matching registered signature")
	err = filterManager.RemoveSignature(notMatchingSignature)
	assert.Error(t, err, "Removing non existing signature from the Manager")
}
