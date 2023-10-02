package streams

import (
	"context"
	"sync"
	"testing"

	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

const (
	policy1Mask     uint64 = 0b1
	policy1And2Mask uint64 = 0b11
	allPoliciesMask uint64 = 0xffffffffffffffff
)

var (
	policy1Event     = trace.Event{MatchedPoliciesUser: 0b1}
	policy2Event     = trace.Event{MatchedPoliciesUser: 0b10}
	policy3Event     = trace.Event{MatchedPoliciesUser: 0b100}
	policy1And2Event = trace.Event{MatchedPoliciesUser: 0b11}
)

func TestStreamManager(t *testing.T) {
	t.Parallel()

	var (
		stream1Count int
		stream2Count int
		stream3Count int
	)

	ctx := context.Background()

	sm := NewStreamsManager()

	// stream for policy1
	stream1 := sm.Subscribe(policy1Mask, 0)

	// stream for policy1 and policy2
	stream2 := sm.Subscribe(policy1And2Mask, 0)

	// stream for all policies
	stream3 := sm.Subscribe(allPoliciesMask, 0)

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
			sm.Publish(ctx, policy1Event)
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(ctx, policy2Event)
		}
		publishersWG.Done()
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sm.Publish(ctx, policy3Event)
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
		name       string
		policyMask uint64
		event      trace.Event
		expected   bool
	}{
		{
			name:       "event matched policy 1, policy mask 1",
			policyMask: 0b1,
			event:      policy1Event,
			expected:   false,
		},
		{
			name:       "event matched policy 1, policy mask 2",
			policyMask: 0b10,
			event:      policy1Event,
			expected:   true,
		},
		{
			name:       "event matched policy 1, catch all policy mask",
			policyMask: 0xffffffffffffffff,
			event:      policy1Event,
			expected:   false,
		},
		{
			name:       "event matched policy 1 and policy 2, policy mask 1",
			policyMask: 0b1,
			event:      policy1And2Event,
			expected:   false,
		},
		{
			name:       "event matched policy 1 and policy 2, policy mask 2",
			policyMask: 0b10,
			event:      policy1And2Event,
			expected:   false,
		},
		{
			name:       "event matched policy 1 and policy 2, catch all policy mask",
			policyMask: 0xffffffffffffffff,
			event:      policy1And2Event,
			expected:   false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stream := sm.Subscribe(tt.policyMask, 0)
			assert.Equal(t, tt.expected, stream.shouldIgnorePolicy(tt.event))
		})
	}
}
