package streams

import (
	"sync"
	"testing"

	"gotest.tools/assert"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// ns builds a policy-name set for Subscribe.
func ns(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

func mustConvertEvent(e *trace.Event) *pb.Event {
	pbEvent, err := events.ConvertTraceeEventToProto(*e)
	if err != nil {
		panic(err)
	}
	return pbEvent
}

func TestStreamManager(t *testing.T) {
	t.Parallel()

	// Event content is irrelevant to routing — streams route on the matched policy NAMES
	// passed to Publish, not on any event field.
	policy1Event := mustConvertEvent(&trace.Event{})
	policy2Event := mustConvertEvent(&trace.Event{})
	policy3Event := mustConvertEvent(&trace.Event{})

	var (
		stream1Count int
		stream2Count int
		stream3Count int
	)

	sm := NewStreamsManager()

	stream1 := sm.Subscribe(ns("policy1"), map[int32]struct{}{}, config.StreamBuffer{})            // policy1 only
	stream2 := sm.Subscribe(ns("policy1", "policy2"), map[int32]struct{}{}, config.StreamBuffer{}) // policy1 + policy2
	stream3 := sm.Subscribe(nil, map[int32]struct{}{}, config.StreamBuffer{})                      // all policies

	// consumers
	consumersWG := &sync.WaitGroup{}
	consumersWG.Add(3)

	go func() {
		for range stream1.ReceiveEvents() {
			stream1Count++
		}
		consumersWG.Done()
	}()

	go func() {
		for range stream2.ReceiveEvents() {
			stream2Count++
		}
		consumersWG.Done()
	}()

	go func() {
		for range stream3.ReceiveEvents() {
			stream3Count++
		}
		consumersWG.Done()
	}()

	// publishers
	publishersWG := &sync.WaitGroup{}
	publishersWG.Add(3)

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(policy1Event, []string{"policy1"})
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(policy2Event, []string{"policy2"})
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(policy3Event, []string{"policy3"})
		}
		publishersWG.Done()
	}()

	publishersWG.Wait()
	sm.Close()
	consumersWG.Wait()

	assert.Equal(t, 100, stream1Count) // only policy1
	assert.Equal(t, 200, stream2Count) // policy1 + policy2
	assert.Equal(t, 300, stream3Count) // all
}

func Test_shouldIgnore(t *testing.T) {
	t.Parallel()

	sm := NewStreamsManager()

	tests := []struct {
		name     string
		policies map[string]struct{} // stream subscription (nil/empty = all)
		matched  []string            // policy names that matched the event
		expected bool                // should the stream ignore the event?
	}{
		{"matched p1, subscribed p1", ns("policy1"), []string{"policy1"}, false},
		{"matched p1, subscribed p2", ns("policy2"), []string{"policy1"}, true},
		{"matched p1, subscribed all (nil)", nil, []string{"policy1"}, false},
		{"matched p1+p2, subscribed p1", ns("policy1"), []string{"policy1", "policy2"}, false},
		{"matched p1+p2, subscribed p2", ns("policy2"), []string{"policy1", "policy2"}, false},
		{"matched p1+p2, subscribed all", nil, []string{"policy1", "policy2"}, false},
		{"matched none, subscribed p1", ns("policy1"), nil, true},
		{"matched p3, subscribed p1+p2", ns("policy1", "policy2"), []string{"policy3"}, true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stream := sm.Subscribe(tt.policies, map[int32]struct{}{}, config.StreamBuffer{})
			assert.Equal(t, tt.expected, stream.shouldIgnore(tt.matched))
		})
	}
}
