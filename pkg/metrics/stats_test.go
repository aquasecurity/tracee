package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
)

func TestStats_ShouldTrackEventForBPFStats(t *testing.T) {
	stats := NewStats()

	tests := []struct {
		name     string
		eventID  events.ID
		expected bool
	}{
		// Common events (should be tracked)
		{
			name:     "StartCommonID boundary",
			eventID:  events.StartCommonID,
			expected: true,
		},
		{
			name:     "Common event in middle range",
			eventID:  events.SysEnter,
			expected: true,
		},
		{
			name:     "MaxCommonID boundary",
			eventID:  events.MaxCommonID,
			expected: true,
		},
		{
			name:     "Just before StartCommonID",
			eventID:  events.StartCommonID - 1,
			expected: false,
		},

		// Common extended events (should be tracked)
		{
			name:     "StartCommonExtendedID boundary",
			eventID:  events.StartCommonExtendedID,
			expected: true,
		},
		{
			name:     "Common extended event in middle range",
			eventID:  events.StartCommonExtendedID + 100,
			expected: true,
		},
		{
			name:     "MaxCommonExtendedID boundary",
			eventID:  events.MaxCommonExtendedID,
			expected: true,
		},
		{
			name:     "Just after MaxCommonExtendedID",
			eventID:  events.MaxCommonExtendedID + 1,
			expected: false,
		},

		// Signal events (should be tracked)
		{
			name:     "StartSignalID boundary",
			eventID:  events.StartSignalID,
			expected: true,
		},
		{
			name:     "Signal event in middle range",
			eventID:  events.SignalCgroupMkdir,
			expected: true,
		},
		{
			name:     "MaxSignalID boundary",
			eventID:  events.MaxSignalID,
			expected: true,
		},
		{
			name:     "Just before StartSignalID",
			eventID:  events.StartSignalID - 1,
			expected: false,
		},

		// Signal extended events (should be tracked)
		{
			name:     "StartSignalExtendedID boundary",
			eventID:  events.StartSignalExtendedID,
			expected: true,
		},
		{
			name:     "Signal extended event in middle range",
			eventID:  events.StartSignalExtendedID + 100,
			expected: true,
		},
		{
			name:     "MaxSignalExtendedID boundary",
			eventID:  events.MaxSignalExtendedID,
			expected: true,
		},
		{
			name:     "Just after MaxSignalExtendedID",
			eventID:  events.MaxSignalExtendedID + 1,
			expected: false,
		},

		// Test events (should be tracked)
		{
			name:     "StartTestID boundary",
			eventID:  events.StartTestID,
			expected: true,
		},
		{
			name:     "Test event in middle range",
			eventID:  events.ExecTest,
			expected: true,
		},
		{
			name:     "MaxTestID boundary",
			eventID:  events.MaxTestID,
			expected: true,
		},
		{
			name:     "Just before StartTestID",
			eventID:  events.StartTestID - 1,
			expected: false,
		},
		{
			name:     "Just after MaxTestID",
			eventID:  events.MaxTestID + 1,
			expected: false,
		},

		// Userspace-derived events (should NOT be tracked)
		{
			name:     "StartUserSpaceID boundary",
			eventID:  events.StartUserSpaceID,
			expected: false,
		},
		{
			name:     "Userspace event in middle range",
			eventID:  events.NetPacketIPv4,
			expected: false,
		},
		{
			name:     "MaxUserSpaceID boundary",
			eventID:  events.MaxUserSpaceID,
			expected: false,
		},

		// Userspace-derived extended events (should NOT be tracked)
		{
			name:     "StartUserSpaceExtendedID boundary",
			eventID:  events.StartUserSpaceExtendedID,
			expected: false,
		},
		{
			name:     "Userspace extended event in middle range",
			eventID:  events.StartUserSpaceExtendedID + 100,
			expected: false,
		},
		{
			name:     "MaxUserSpaceExtendedID boundary",
			eventID:  events.MaxUserSpaceExtendedID,
			expected: false,
		},

		// Capture events (should NOT be tracked)
		{
			name:     "StartCaptureID boundary",
			eventID:  events.StartCaptureID,
			expected: false,
		},
		{
			name:     "Capture event in middle range",
			eventID:  events.CaptureFileWrite,
			expected: false,
		},
		{
			name:     "MaxCaptureID boundary",
			eventID:  events.MaxCaptureID,
			expected: false,
		},

		// Signature events (should NOT be tracked)
		{
			name:     "StartSignatureID boundary",
			eventID:  events.StartSignatureID,
			expected: false,
		},
		{
			name:     "Signature event in middle range",
			eventID:  events.StartSignatureID + 100,
			expected: false,
		},
		{
			name:     "MaxSignatureID boundary",
			eventID:  events.MaxSignatureID,
			expected: false,
		},

		// Signature extended events (should NOT be tracked)
		{
			name:     "StartSignatureExtendedID boundary",
			eventID:  events.StartSignatureExtendedID,
			expected: false,
		},
		{
			name:     "Signature extended event in middle range",
			eventID:  events.StartSignatureExtendedID + 100,
			expected: false,
		},
		{
			name:     "MaxSignatureExtendedID boundary",
			eventID:  events.MaxSignatureExtendedID,
			expected: false,
		},

		// Syscall events (should NOT be tracked - they're below StartCommonID)
		{
			name:     "Syscall Read",
			eventID:  events.Read,
			expected: false,
		},
		{
			name:     "Syscall Write",
			eventID:  events.Write,
			expected: false,
		},
		{
			name:     "Syscall Execve",
			eventID:  events.Execve,
			expected: false,
		},

		// Special/edge case events
		{
			name:     "All event ID",
			eventID:  events.All,
			expected: false,
		},
		{
			name:     "Undefined event ID",
			eventID:  events.Undefined,
			expected: false,
		},
		{
			name:     "Unsupported event ID",
			eventID:  events.Unsupported,
			expected: false,
		},
		{
			name:     "MaxBuiltinID",
			eventID:  events.MaxBuiltinID,
			expected: false,
		},

		// Negative event IDs
		{
			name:     "Negative event ID",
			eventID:  -1,
			expected: false,
		},

		// Very large event IDs
		{
			name:     "Very large event ID",
			eventID:  100000,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stats.ShouldTrackEventForBPFStats(tt.eventID)
			assert.Equal(t, tt.expected, result, "ShouldTrackEventForBPFStats(%d) should return %v", tt.eventID, tt.expected)
		})
	}
}

// TestShouldTrackEventForBPFStats_RangeValidation tests that the method correctly
// handles all defined event ranges according to the documentation
func TestShouldTrackEventForBPFStats_RangeValidation(t *testing.T) {
	stats := NewStats()

	// Test that all events in tracked ranges return true
	trackedRanges := []struct {
		name  string
		start events.ID
		end   events.ID
	}{
		{"Common events", events.StartCommonID, events.MaxCommonExtendedID},
		{"Signal events", events.StartSignalID, events.MaxSignalExtendedID},
		{"Test events", events.StartTestID, events.MaxTestID},
	}

	for _, tr := range trackedRanges {
		t.Run(tr.name, func(t *testing.T) {
			// Test start boundary
			assert.True(t, stats.ShouldTrackEventForBPFStats(tr.start), "Expected event ID %d (start of %s) to be tracked", tr.start, tr.name)

			// Test end boundary
			assert.True(t, stats.ShouldTrackEventForBPFStats(tr.end), "Expected event ID %d (end of %s) to be tracked", tr.end, tr.name)

			// Test middle of range
			middle := tr.start + (tr.end-tr.start)/2
			assert.True(t, stats.ShouldTrackEventForBPFStats(middle), "Expected event ID %d (middle of %s) to be tracked", middle, tr.name)
		})
	}

	// Test that all events in non-tracked ranges return false
	nonTrackedRanges := []struct {
		name  string
		start events.ID
		end   events.ID
	}{
		{"Userspace events", events.StartUserSpaceID, events.MaxUserSpaceExtendedID},
		{"Capture events", events.StartCaptureID, events.MaxCaptureID},
		{"Signature events", events.StartSignatureID, events.MaxSignatureExtendedID},
	}

	for _, ntr := range nonTrackedRanges {
		t.Run(ntr.name, func(t *testing.T) {
			// Test start boundary
			assert.False(t, stats.ShouldTrackEventForBPFStats(ntr.start), "Expected event ID %d (start of %s) to NOT be tracked", ntr.start, ntr.name)

			// Test end boundary
			assert.False(t, stats.ShouldTrackEventForBPFStats(ntr.end), "Expected event ID %d (end of %s) to NOT be tracked", ntr.end, ntr.name)

			// Test middle of range
			middle := ntr.start + (ntr.end-ntr.start)/2
			assert.False(t, stats.ShouldTrackEventForBPFStats(middle), "Expected event ID %d (middle of %s) to NOT be tracked", middle, ntr.name)
		})
	}
}

// TestShouldTrackEventForBPFStats_GapsBetweenRanges tests that gaps between
// event ranges are correctly handled (should return false)
func TestShouldTrackEventForBPFStats_GapsBetweenRanges(t *testing.T) {
	stats := NewStats()

	gaps := []struct {
		name    string
		eventID events.ID
	}{
		{"Gap between MaxCommonExtendedID and StartUserSpaceID", events.MaxCommonExtendedID + 1},
		{"Gap between MaxUserSpaceExtendedID and StartCaptureID", events.MaxUserSpaceExtendedID + 1},
		// Note: MaxCaptureID + 1 == StartSignalID (no gap)
		{"Gap between MaxSignalExtendedID and StartSignatureID", events.MaxSignalExtendedID + 1},
		// Note: MaxSignatureExtendedID + 1 == StartTestID (no gap)
	}

	for _, gap := range gaps {
		t.Run(gap.name, func(t *testing.T) {
			assert.False(t, stats.ShouldTrackEventForBPFStats(gap.eventID), "Expected event ID %d (%s) to NOT be tracked", gap.eventID, gap.name)
		})
	}
}
