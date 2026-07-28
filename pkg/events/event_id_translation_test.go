package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func TestTranslateEventID_BuiltinEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		eventID  int
		expected pb.EventId
	}{
		{
			name:     "Read syscall",
			eventID:  int(Read),
			expected: pb.EventId_read,
		},
		{
			name:     "Write syscall",
			eventID:  int(Write),
			expected: pb.EventId_write,
		},
		{
			name:     "Execve syscall",
			eventID:  int(Execve),
			expected: pb.EventId_execve,
		},
		{
			name:     "Open syscall",
			eventID:  int(Open),
			expected: pb.EventId_open,
		},
		{
			name:     "Close syscall",
			eventID:  int(Close),
			expected: pb.EventId_close,
		},
		{
			name:     "NetPacketIPv4 user-space event",
			eventID:  int(NetPacketIPv4),
			expected: pb.EventId_net_packet_ipv4,
		},
		{
			name:     "ContainerCreate user-space event",
			eventID:  int(ContainerCreate),
			expected: pb.EventId_container_create,
		},
		{
			name:     "SchedProcessFork common event",
			eventID:  int(SchedProcessFork),
			expected: pb.EventId_sched_process_fork,
		},
		{
			name:     "MaxBuiltinID boundary (excluded from table)",
			eventID:  int(MaxBuiltinID),
			expected: pb.EventId(MaxBuiltinID), // Returns ID directly since array has MaxBuiltinID elements (0 to MaxBuiltinID-1)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := TranslateEventID(tt.eventID)
			assert.Equal(t, tt.expected, result, "Event ID %d should translate to %v", tt.eventID, tt.expected)
		})
	}
}

func TestTranslateEventID_NonBuiltinEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		eventID  int
		expected pb.EventId
	}{
		{
			name:     "Event above MaxBuiltinID",
			eventID:  int(MaxBuiltinID) + 1,
			expected: pb.EventId(int(MaxBuiltinID) + 1),
		},
		{
			name:     "Large event ID",
			eventID:  15000,
			expected: pb.EventId(15000),
		},
		{
			name:     "Very large event ID",
			eventID:  50000,
			expected: pb.EventId(50000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := TranslateEventID(tt.eventID)
			assert.Equal(t, tt.expected, result, "Event ID %d should translate to %v", tt.eventID, tt.expected)
		})
	}
}

func TestTranslateEventID_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		eventID  int
		expected pb.EventId
	}{
		{
			name:     "Zero event ID",
			eventID:  0,
			expected: EventTranslationTable[0],
		},
		{
			name:     "Negative event ID",
			eventID:  -1,
			expected: pb.EventId(-1), // Should return as-is since it's > MaxBuiltinID check fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := TranslateEventID(tt.eventID)
			assert.Equal(t, tt.expected, result, "Event ID %d should translate to %v", tt.eventID, tt.expected)
		})
	}
}

func TestEventTranslationTable_Completeness(t *testing.T) {
	t.Parallel()

	// Verify that the translation table has the correct size
	require.Equal(t, int(MaxBuiltinID), len(EventTranslationTable), "Translation table should have MaxBuiltinID entries")

	// Verify that some key events are properly mapped
	keyEvents := map[ID]pb.EventId{
		Read:            pb.EventId_read,
		Write:           pb.EventId_write,
		Execve:          pb.EventId_execve,
		NetPacketIPv4:   pb.EventId_net_packet_ipv4,
		ContainerCreate: pb.EventId_container_create,
	}

	for internalID, expectedProtoID := range keyEvents {
		if int(internalID) < len(EventTranslationTable) {
			actualProtoID := EventTranslationTable[internalID]
			assert.Equal(t, expectedProtoID, actualProtoID,
				"Event %d (%v) should map to %v, but got %v",
				internalID, internalID, expectedProtoID, actualProtoID)
		}
	}
}

func TestTranslateEventID_Consistency(t *testing.T) {
	t.Parallel()

	// Test that TranslateEventID and direct table access give the same result
	// for built-in events
	testEvents := []ID{Read, Write, Execve, Open, Close, NetPacketIPv4, ContainerCreate}

	for _, eventID := range testEvents {
		if int(eventID) <= int(MaxBuiltinID) {
			directAccess := EventTranslationTable[eventID]
			viaFunction := TranslateEventID(int(eventID))
			assert.Equal(t, directAccess, viaFunction,
				"Direct table access and TranslateEventID should match for event %d", eventID)
		}
	}
}

func TestTranslateFromProtoEventID_BuiltinEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		protoID    pb.EventId
		expectedID ID
	}{
		{"read (proto 1 -> internal 0)", pb.EventId_read, Read},
		{"write", pb.EventId_write, Write},
		{"execve", pb.EventId_execve, Execve},
		{"openat", pb.EventId_openat, Openat},
		{"sched_process_exec", pb.EventId_sched_process_exec, SchedProcessExec},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expectedID, TranslateFromProtoEventID(tt.protoID))
		})
	}
}

func TestTranslateFromProtoEventID_EdgeCases(t *testing.T) {
	t.Parallel()

	// Unspecified carries no identity: it must NOT resolve to some unmapped
	// internal ID (regression test for the linear-search implementation)
	assert.Equal(t, Undefined, TranslateFromProtoEventID(pb.EventId_unspecified))

	// IDs above MaxUserSpaceID have no protobuf mapping and pass through
	// unchanged (signature, detector and test event ranges)
	assert.Equal(t, StartDetectorID, TranslateFromProtoEventID(pb.EventId(StartDetectorID)))
	assert.Equal(t, StartSignatureID, TranslateFromProtoEventID(pb.EventId(StartSignatureID)))

	// Unsupported (9000) has no table entry and passes through unchanged
	assert.Equal(t, Unsupported, TranslateFromProtoEventID(pb.EventId(Unsupported)))
}

func TestTranslateFromProtoEventID_InverseOfTranslateEventID(t *testing.T) {
	t.Parallel()

	// For every mapped table entry, reverse-then-forward must return the same
	// protobuf ID. (Reverse alone may pick the lowest of duplicate internal
	// IDs, so the assertion goes through the table.)
	for internalID, protoID := range EventTranslationTable {
		if protoID == pb.EventId_unspecified {
			continue
		}
		reversed := TranslateFromProtoEventID(protoID)
		require.Less(t, int(reversed), len(EventTranslationTable),
			"reversed ID for proto %v out of table range", protoID)
		assert.Equal(t, protoID, EventTranslationTable[reversed],
			"proto %v (from internal %d) did not survive reverse translation", protoID, internalID)
	}
}
