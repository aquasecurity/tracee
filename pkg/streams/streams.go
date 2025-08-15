package streams

import (
	"context"
	"sync"

	"github.com/aquasecurity/tracee/types/trace"
)

// Stream is a stream of events
type Stream struct {
	policies map[string]bool // policies that this stream is interested in, empty means all
	// events is a channel that is used to receive events from the stream
	events chan trace.Event
}

// ReceiveEvents returns a read-only channel for receiving events from the stream
func (s *Stream) ReceiveEvents() <-chan trace.Event {
	return s.events
}

// Publish publishes an event to the stream,
// but first check if this stream is interested in this event,
// by checking the event's policy mask against the stream's policy mask.
func (s *Stream) publish(ctx context.Context, event trace.Event) {
	if !s.shouldPublish(event) {
		return
	}

	// Currently, the behavior is to block when the channel is full.
	// However, there is a consideration to modify this behavior to drop events instead.
	// This change is based on the notion that with multiple streams, one stream's events
	// should not impede another stream's event reception if they aren't processed rapidly.
	// It is worth noting that there are scenarios where blocking may be preferred.
	// To accommodate both scenarios, the plan is to introduce configurability for this behavior in the future.
	// TODO: allow this to be configurable (drop/block) (josedonizetti)
	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	}
}

// shouldPublish checks if event matches subscribed policies
func (s *Stream) shouldPublish(event trace.Event) bool {
	// No policies means subscribe to all
	if len(s.policies) == 0 {
		return true
	}

	// Check if any of the event's matched policies are in our subscription
	for _, matchedPolicy := range event.MatchedPolicies {
		if s.policies[matchedPolicy] {
			return true
		}
	}
	return false
}

// close closes the stream
func (s *Stream) close() {
	close(s.events)
}

// StreamManager manages streams
type StreamsManager struct {
	mutex       sync.Mutex
	subscribers map[*Stream]struct{}
}

// NewStreamManager creates a new stream manager
func NewStreamsManager() *StreamsManager {
	return &StreamsManager{
		mutex:       sync.Mutex{},
		subscribers: make(map[*Stream]struct{}),
	}
}

// Subscribe adds a stream to the manager
func (sm *StreamsManager) Subscribe(policyNames []string, chanSize int) *Stream {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream := &Stream{
		policies: make(map[string]bool),
		events:   make(chan trace.Event, chanSize),
	}

	for _, policyName := range policyNames {
		stream.policies[policyName] = true
	}

	sm.subscribers[stream] = struct{}{}

	return stream
}

// Unsubscribe removes a stream from the manager
func (sm *StreamsManager) Unsubscribe(stream *Stream) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// check if stream is subscribed
	if _, ok := sm.subscribers[stream]; ok {
		delete(sm.subscribers, stream)
		stream.close()
	}
}

// Publish publishes an event to all streams
func (sm *StreamsManager) Publish(ctx context.Context, event trace.Event) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for stream := range sm.subscribers {
		stream.publish(ctx, event)
	}
}

// Close closes all streams
func (sm *StreamsManager) Close() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	for stream := range sm.subscribers {
		delete(sm.subscribers, stream)
		stream.close()
	}
}
