package initialize

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_CreateEventsFromSigs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		startId    int
		signatures []detect.Signature
		expected   []extensions.Definition
	}{
		{
			name:    "fake_event_0",
			startId: int(6001),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_0",
					[]string{
						"hooked_syscall",
					},
				),
			},
			expected: []extensions.Definition{
				extensions.NewDefinition(
					int(6001),                         // id,
					extensions.Sys32Undefined,         // id32
					"fake_event_0",                    // eventName
					extensions.NewVersion(1, 0, 0),    // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					extensions.NewDependencies(
						[]int{extensions.HookedSyscall},
						[]extensions.KSymDep{},
						[]extensions.ProbeDep{},
						[]extensions.TailCall{},
						extensions.CapsDep{},
					),
					[]trace.ArgMeta{},
					nil,
				),
			},
		},
		{
			name:    "fake_event_1/2",
			startId: int(6010),
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
			expected: []extensions.Definition{
				extensions.NewDefinition(
					int(6010),                         // id,
					extensions.Sys32Undefined,         // id32
					"fake_event_1",                    // eventName
					extensions.NewVersion(1, 0, 0),    // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					extensions.NewDependencies(
						[]int{extensions.Ptrace},
						[]extensions.KSymDep{},
						[]extensions.ProbeDep{},
						[]extensions.TailCall{},
						extensions.CapsDep{},
					),
					[]trace.ArgMeta{},
					nil,
				),
				extensions.NewDefinition(
					int(6011),                         // id,
					extensions.Sys32Undefined,         // id32
					"fake_event_2",                    // eventName
					extensions.NewVersion(1, 0, 0),    // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					extensions.NewDependencies(
						[]int{
							extensions.SecurityFileOpen,
							extensions.SecurityInodeRename,
						},
						[]extensions.KSymDep{},
						[]extensions.ProbeDep{},
						[]extensions.TailCall{},
						extensions.CapsDep{},
					),
					[]trace.ArgMeta{},
					nil,
				),
			},
		},
		{
			name:    "fake_event_3",
			startId: int(6100),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_3",
					[]string{
						"sched_process_exec",
						"security_socket_connect",
					},
				),
			},
			expected: []extensions.Definition{
				extensions.NewDefinition(
					int(6100),                         // id,
					extensions.Sys32Undefined,         // id32
					"fake_event_3",                    // eventName
					extensions.NewVersion(1, 0, 0),    // version
					"fake_description",                // description
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					extensions.NewDependencies(
						[]int{
							extensions.SchedProcessExec,
							extensions.SecuritySocketConnect,
						},
						[]extensions.KSymDep{},
						[]extensions.ProbeDep{},
						[]extensions.TailCall{},
						extensions.CapsDep{},
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
				eventDefID, ok := extensions.Definitions.GetIDByNameFromAny(expected.GetName())
				assert.True(t, ok)
				eventDefinition := extensions.Definitions.GetByIDFromAny(eventDefID)

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
