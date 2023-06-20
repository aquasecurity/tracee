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
	if events.Definitions == nil {
		events.Definitions = events.NewEventGroup()
		err := events.Definitions.AddBatch(events.CoreDefinitions)
		assert.NoError(t, err)
	}

	tests := []struct {
		startId        events.ID
		signatures     []detect.Signature
		expectedEvents []*events.Event
	}{
		{
			startId: events.ID(6001),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_0",
					[]string{
						"hooked_syscalls",
					},
				),
			},
			expectedEvents: []*events.Event{
				events.NewEvent(
					events.ID(6001),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_0",                    // eventName
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{events.HookedSyscalls}, // ids
						nil,                                // probes
						nil,                                // ksyms
						nil,                                // tailcalls
						nil,                                // capabilities
					),
					[]trace.ArgMeta{},
				),
			},
		},
		{
			startId: events.ID(6010),
			signatures: []detect.Signature{
				newFakeSignature(
					"fake_event_1",
					[]string{
						"ptrace",
					},
				),
				newFakeSignature(
					"fake_event_2",
					[]string{
						"security_file_open", "security_inode_rename",
					},
				),
			},
			expectedEvents: []*events.Event{
				events.NewEvent(
					events.ID(6010),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_1",                    // eventName
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{events.Ptrace}, // ids
						nil,                        // probes
						nil,                        // ksyms
						nil,                        // tailcalls
						nil,                        // capabilities
					),
					[]trace.ArgMeta{},
				),
				events.NewEvent(
					events.ID(6011),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_2",                    // eventName
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{
							events.SecurityFileOpen,
							events.SecurityInodeRename,
						}, // ids
						nil, // probes
						nil, // ksyms
						nil, // tailcalls
						nil, // capabilities
					),
					[]trace.ArgMeta{},
				),
			},
		},
		{
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
			expectedEvents: []*events.Event{
				events.NewEvent(
					events.ID(6100),                   // id,
					events.Sys32Undefined,             // id32
					"fake_event_3",                    // eventName
					"",                                // docPath
					false,                             // internal
					false,                             // syscall
					[]string{"signatures", "default"}, // sets
					events.NewDependencies(
						[]events.ID{
							events.SchedProcessExec,
							events.SecuritySocketConnect,
						}, // ids
						nil, // probes
						nil, // ksyms
						nil, // tailcalls
						nil, // capabilities
					),
					[]trace.ArgMeta{},
				),
			},
		},
	}

	for _, test := range tests {
		CreateEventsFromSignatures(test.startId, test.signatures)

		for _, expected := range test.expectedEvents {
			eventID, ok := events.Definitions.GetEventIDByName(expected.GetName())
			assert.True(t, ok)
			event := events.Definitions.GetEventByID(eventID)

			assert.Equal(t, expected.GetID(), event.GetID())
			assert.Equal(t, expected.GetID32Bit(), event.GetID32Bit())
			assert.Equal(t, expected.GetName(), event.GetName())
			assert.Equal(t, expected.GetDocPath(), event.GetDocPath())
			assert.Equal(t, expected.IsInternal(), event.IsInternal())
			assert.Equal(t, expected.IsSyscall(), event.IsSyscall())
			assert.ElementsMatch(t, expected.GetSets(), event.GetSets())
			assert.ElementsMatch(t, expected.GetParams(), event.GetParams())
			assert.ElementsMatch(t, expected.GetDependencies().GetEvents(), event.GetDependencies().GetEvents())
		}
	}
}

func newFakeSignature(name string, deps []string) detect.Signature {
	return &signature.FakeSignature{
		FakeGetMetadata: func() (detect.SignatureMetadata, error) {
			return detect.SignatureMetadata{
				EventName: name,
			}, nil
		},
		FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
			selectedEvents := make([]detect.SignatureEventSelector, 0, len(deps))

			for _, d := range deps {
				eventSelector := detect.SignatureEventSelector{Name: d}
				selectedEvents = append(selectedEvents, eventSelector)
			}

			return selectedEvents, nil
		},
	}
}
