package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

func Test_createEventsFromSigs(t *testing.T) {
	tests := []struct {
		startId        events.ID
		signatures     []detect.Signature
		expectedEvents []events.Event
	}{
		{
			startId: events.ID(6001),
			signatures: []detect.Signature{
				newFakeSignature("fake_event_0", []string{"hooked_syscalls"}),
			},
			expectedEvents: []events.Event{
				events.NewEventDefinition("fake_event_0", []string{"signatures", "default"}, []events.ID{events.HookedSyscalls}),
			},
		},
		{
			startId: events.ID(6010),
			signatures: []detect.Signature{
				newFakeSignature("fake_event_1", []string{"ptrace"}),
				newFakeSignature("fake_event_2", []string{"security_file_open", "security_inode_rename"}),
			},
			expectedEvents: []events.Event{
				events.NewEventDefinition("fake_event_1", []string{"signatures", "default"}, []events.ID{events.Ptrace}),
				events.NewEventDefinition("fake_event_2", []string{"signatures", "default"}, []events.ID{events.SecurityFileOpen, events.SecurityInodeRename}),
			},
		},
		{
			startId: events.ID(6100),
			signatures: []detect.Signature{
				newFakeSignature("fake_event_3", []string{"sched_process_exec", "security_socket_connect"}),
			},
			expectedEvents: []events.Event{
				events.NewEventDefinition("fake_event_3", []string{"signatures", "default"}, []events.ID{events.SchedProcessExec, events.SecuritySocketConnect}),
			},
		},
	}

	for _, test := range tests {
		createEventsFromSignatures(test.startId, test.signatures)

		for _, expected := range test.expectedEvents {
			eventID, ok := events.Definitions.GetID(expected.Name)
			assert.True(t, ok)
			event := events.Definitions.Get(eventID)
			assert.Equal(t, expected, event)
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
