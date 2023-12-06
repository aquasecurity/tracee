package initialize

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_CreateEventsFromSigs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		startId    events.ID
		signatures []detect.Signature
		expected   []events.Definition
	}{
		{
			name:    "fake_event_0",
			startId: events.ID(6001),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_0",
					[]string{
						"hooked_syscall",
					},
				),
			},
			expected: []events.Definition{
				events.NewDefinition(
					events.ID(6001),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_0",                    // eventName
					events.NewVersion(1, 0, 0),        // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{events.HookedSyscall},
						[]events.KSymbol{},
						[]events.Probe{},
						[]events.TailCall{},
						events.Capabilities{},
					),
					[]trace.ArgMeta{},
					nil,
				),
			},
		},
		{
			name:    "fake_event_1/2",
			startId: events.ID(6010),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_1",
					[]string{"ptrace"},
				),
				newFakeSignature(
					"fake_event_2",
					[]string{"security_file_open", "security_inode_rename"},
				),
			},
			expected: []events.Definition{
				events.NewDefinition(
					events.ID(6010),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_1",                    // eventName
					events.NewVersion(1, 0, 0),        // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{events.Ptrace},
						[]events.KSymbol{},
						[]events.Probe{},
						[]events.TailCall{},
						events.Capabilities{},
					),
					[]trace.ArgMeta{},
					nil,
				),
				events.NewDefinition(
					events.ID(6011),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_2",                    // eventName
					events.NewVersion(1, 0, 0),        // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{
							events.SecurityFileOpen,
							events.SecurityInodeRename,
						},
						[]events.KSymbol{},
						[]events.Probe{},
						[]events.TailCall{},
						events.Capabilities{},
					),
					[]trace.ArgMeta{},
					nil,
				),
			},
		},
		{
			name:    "fake_event_3",
			startId: events.ID(6100),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_3",
					[]string{
						"sched_process_exec",
						"security_socket_connect",
					},
				),
			},
			expected: []events.Definition{
				events.NewDefinition(
					events.ID(6100),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_3",                    // eventName
					events.NewVersion(1, 0, 0),        // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{
							events.SchedProcessExec,
							events.SecuritySocketConnect,
						},
						[]events.KSymbol{},
						[]events.Probe{},
						[]events.TailCall{},
						events.Capabilities{},
					),
					[]trace.ArgMeta{},
					nil,
				),
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			CreateEventsFromSignatures(test.startId, test.signatures)

			for _, expected := range test.expected {
				eventDefID, ok := events.Core.GetDefinitionIDByName(expected.GetName())
				assert.True(t, ok)
				eventDefinition := events.Core.GetDefinitionByID(eventDefID)

				assert.Equal(t, expected.GetID(), eventDefinition.GetID())
				assert.Equal(t, expected.GetID32Bit(), eventDefinition.GetID32Bit())
				assert.Equal(t, expected.GetName(), eventDefinition.GetName())
				assert.Equal(t, expected.GetDocPath(), eventDefinition.GetDocPath())
				assert.Equal(t, expected.IsInternal(), eventDefinition.IsInternal())
				assert.Equal(t, expected.IsSyscall(), eventDefinition.IsSyscall())
				assert.ElementsMatch(t, expected.GetSets(), eventDefinition.GetSets())
				assert.ElementsMatch(t, expected.GetParams(), eventDefinition.GetParams())

				dependencies := eventDefinition.GetDependencies()
				expDependencies := expected.GetDependencies()
				assert.ElementsMatch(t, expDependencies.GetIDs(), dependencies.GetIDs())
			}
		})
	}
}

func newFakeSignature(name string, deps []string) detect.Signature {
	return &signature.FakeSignature{
		FakeGetMetadata: func() (detect.SignatureMetadata, error) {
			return detect.SignatureMetadata{
				EventName:   name,
				Description: "fake_description",
				Version:     "1.0.0",
			}, nil
		},
		FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
			selectedEvents := make([]detect.SignatureEventSelector, 0, len(deps))

			for _, d := range deps {
				eventSelector := detect.SignatureEventSelector{Name: d, Source: "tracee", Origin: "*"}
				selectedEvents = append(selectedEvents, eventSelector)
			}

			return selectedEvents, nil
		},
	}
}
