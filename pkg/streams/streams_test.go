package streams

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

const (
	policy1Mask     uint64 = 0b1
	policy1And2Mask uint64 = 0b11
	allPoliciesMask uint64 = 0xffffffffffffffff
)

var (
	policy1Event     = trace.Event{MatchedRulesUser: 0b1}
	policy2Event     = trace.Event{MatchedRulesUser: 0b10}
	policy3Event     = trace.Event{MatchedRulesUser: 0b100}
	policy1And2Event = trace.Event{MatchedRulesUser: 0b11}
)

func TestStreamManager_PublishAndReceive(t *testing.T) {
	sm := NewStreamsManager()
	ctx := context.Background()

	event := trace.Event{
		MatchedPolicies: []string{"policy1"},
	}

	// Subscribe with matching policy
	stream1 := sm.Subscribe([]string{"policy1"}, 1)

	// Subscribe with non-matching policy
	stream2 := sm.Subscribe([]string{"policy2"}, 1)

	// Subscribe to all policies
	stream3 := sm.Subscribe([]string{}, 1)

	// Publish event
	sm.Publish(ctx, event)

	// Check stream1 received event (matching policy)
	select {
	case receivedEvent := <-stream1.ReceiveEvents():
		assert.Equal(t, event, receivedEvent)
	default:
		t.Error("Expected stream1 to receive event")
	}

	// Check stream2 did not receive event (non-matching policy)
	select {
	case <-stream2.ReceiveEvents():
		t.Error("Stream2 should not receive event")
	default:
		// Expected - no event received
	}

	// Check stream3 received event (all policies)
	select {
	case receivedEvent := <-stream3.ReceiveEvents():
		assert.Equal(t, event, receivedEvent)
	default:
		t.Error("Expected stream3 to receive event")
	}
}

func TestStreamManager_MultiplePolices(t *testing.T) {
	sm := NewStreamsManager()
	ctx := context.Background()

	tests := []struct {
		name    string
		streams []struct {
			policies []string
			expect   bool
		}
		event trace.Event
	}{
		{
			name: "multiple streams with different policies",
			streams: []struct {
				policies []string
				expect   bool
			}{
				{policies: []string{"policy1", "policy2"}, expect: true},
				{policies: []string{"policy3"}, expect: false},
				{policies: []string{}, expect: true}, // all policies
			},
			event: trace.Event{
				MatchedPolicies: []string{"policy1"},
			},
		},
		{
			name: "overlapping policies between streams",
			streams: []struct {
				policies []string
				expect   bool
			}{
				{policies: []string{"policy1"}, expect: true},
				{policies: []string{"policy1", "policy2"}, expect: true},
				{policies: []string{"policy2", "policy3"}, expect: false},
			},
			event: trace.Event{
				MatchedPolicies: []string{"policy1"},
			},
		},
		{
			name: "event matching multiple policies",
			streams: []struct {
				policies []string
				expect   bool
			}{
				{policies: []string{"policy1"}, expect: true},
				{policies: []string{"policy2"}, expect: true},
				{policies: []string{"policy3"}, expect: false},
			},
			event: trace.Event{
				MatchedPolicies: []string{"policy1", "policy2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var streams []*Stream

			// Create streams with different policies
			for _, s := range tt.streams {
				stream := sm.Subscribe(s.policies, 1)
				streams = append(streams, stream)
			}

			// Publish event
			sm.Publish(ctx, tt.event)

			// Check each stream
			for i, s := range tt.streams {
				select {
				case evt := <-streams[i].ReceiveEvents():
					if !s.expect {
						t.Errorf("Stream %d received unexpected event: %v", i, evt)
					}
					assert.Equal(t, tt.event, evt)
				default:
					if s.expect {
						t.Errorf("Stream %d did not receive expected event", i)
					}
				}
			}

			// Cleanup
			for _, stream := range streams {
				sm.Unsubscribe(stream)
			}
		})
	}
}
