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

const (
	policy1Mask     uint64 = 0b1
	policy1And2Mask uint64 = 0b11
	allPoliciesMask uint64 = 0xffffffffffffffff
)

var (
	// Create pb.Events for testing
	policy1Event = mustConvertEvent(&trace.Event{MatchedPoliciesUser: 0b1})
	policy2Event = mustConvertEvent(&trace.Event{MatchedPoliciesUser: 0b10})
	policy3Event = mustConvertEvent(&trace.Event{MatchedPoliciesUser: 0b100})
)

func mustConvertEvent(e *trace.Event) *pb.Event {
	pbEvent, err := events.ConvertTraceeEventToProto(*e)
	if err != nil {
		panic(err)
	}
	return pbEvent
}

func TestStreamManager(t *testing.T) {
	t.Parallel()

	var (
		stream1Count int
		stream2Count int
		stream3Count int
	)

	sm := NewStreamsManager()

	// stream for policy1
	stream1 := sm.Subscribe(policy1Mask, map[int32]struct{}{}, config.StreamBuffer{})

	// stream for policy1 and policy2
	stream2 := sm.Subscribe(policy1And2Mask, map[int32]struct{}{}, config.StreamBuffer{})

	// stream for all policies
	stream3 := sm.Subscribe(allPoliciesMask, map[int32]struct{}{}, config.StreamBuffer{})

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
			sm.Publish(policy1Event, 0b1)
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(policy2Event, 0b10)
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(policy3Event, 0b100)
		}
		publishersWG.Done()
	}()

	publishersWG.Wait()
	sm.Close()
	consumersWG.Wait()

	assert.Equal(t, 100, stream1Count)
	assert.Equal(t, 200, stream2Count)
	assert.Equal(t, 300, stream3Count)
}

func Test_shouldIgnorePolicy(t *testing.T) {
	t.Parallel()

	sm := NewStreamsManager()

	tests := []struct {
		name         string
		policyMask   uint64
		policyBitmap uint64
		expected     bool
	}{
		{
			name:         "event matched policy 1, policy mask 1",
			policyMask:   0b1,
			policyBitmap: 0b1,
			expected:     false,
		},
		{
			name:         "event matched policy 1, policy mask 2",
			policyMask:   0b10,
			policyBitmap: 0b1,
			expected:     true,
		},
		{
			name:         "event matched policy 1, catch all policy mask",
			policyMask:   0xffffffffffffffff,
			policyBitmap: 0b1,
			expected:     false,
		},
		{
			name:         "event matched policy 1 and policy 2, policy mask 1",
			policyMask:   0b1,
			policyBitmap: 0b11,
			expected:     false,
		},
		{
			name:         "event matched policy 1 and policy 2, policy mask 2",
			policyMask:   0b10,
			policyBitmap: 0b11,
			expected:     false,
		},
		{
			name:         "event matched policy 1 and policy 2, catch all policy mask",
			policyMask:   0xffffffffffffffff,
			policyBitmap: 0b11,
			expected:     false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stream := sm.Subscribe(tt.policyMask, map[int32]struct{}{}, config.StreamBuffer{})
			assert.Equal(t, tt.expected, stream.shouldIgnorePolicy(tt.policyBitmap))
		})
	}
}
