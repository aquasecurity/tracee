package streams

import (
	"context"
	"sync"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// Stream is a stream of events
type Stream struct {
	// policy mask is a bitmap of policies that this stream is interested in
	policyMask uint64
	// event to filter
	eventMap map[events.ID]struct{}
	// true if there is at least one element in the eventMap
	eventFilter bool
	// events is a channel that is used to receive events from the stream
	events       chan trace.Event
	strategyPush func(context.Context, trace.Event)
}

// ReceiveEvents returns a read-only channel for receiving events from the stream
func (s *Stream) ReceiveEvents() <-chan trace.Event {
	return s.events
}

func (s *Stream) publish(ctx context.Context, event trace.Event) {
	if s.shouldIgnorePolicy(event) {
		return
	}

	if s.eventFilter {
		if _, ok := s.eventMap[events.ID(event.EventID)]; !ok {
			return
		}
	}

	// Due to the dynamic nature of this function the compile doesn't
	// inline this. A condition is faster (and cheaper) than a function call
	// should we change it with a condition?
	s.strategyPush(ctx, event)
}

func (s *Stream) blockPublish(ctx context.Context, event trace.Event) {
	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	}
}

func (s *Stream) dropPublish(ctx context.Context, event trace.Event) {
	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	default:
		// Probably this is going to be too verbose
		logger.Debugw("stream channel full, dropping message")
	}
}

// shouldIgnorePolicy checks if the stream should ignore the event
func (s *Stream) shouldIgnorePolicy(event trace.Event) bool {
	return s.policyMask&event.MatchedPoliciesUser == 0
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
func (sm *StreamsManager) Subscribe(policyMask uint64, eventMap map[events.ID]struct{}, bufferConfig config.StreamBuffer) *Stream {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream := &Stream{
		policyMask:  policyMask,
		events:      make(chan trace.Event, bufferConfig.Size),
		eventMap:    eventMap,
		eventFilter: len(eventMap) > 0,
	}

	switch bufferConfig.Mode {
	case "", config.StreamBufferBlock:
		stream.strategyPush = stream.blockPublish
	case config.StreamBufferDrop:
		stream.strategyPush = stream.dropPublish
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
