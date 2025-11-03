package streams

import (
	"context"
	"sync"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/types/trace"
)

// Stream is a stream of events
type Stream struct {
	// policy mask is a bitmap of policies that this stream is interested in
	policyMask uint64
	// events is a channel that is used to receive events from the stream
	events  chan trace.Event
	publish func(context.Context, trace.Event)
}

// ReceiveEvents returns a read-only channel for receiving events from the stream
func (s *Stream) ReceiveEvents() <-chan trace.Event {
	return s.events
}

// Publish publishes an event to the stream,
// but first check if this stream is interested in this event,
// by checking the event's policy mask against the stream's policy mask.
func (s *Stream) blockPublish(ctx context.Context, event trace.Event) {
	if s.shouldIgnorePolicy(event) {
		return
	}

	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	}
}

func (s *Stream) dropPublish(ctx context.Context, event trace.Event) {
	if s.shouldIgnorePolicy(event) {
		return
	}

	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	default:
		// Probably this is too verbose
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
func (sm *StreamsManager) Subscribe(policyMask uint64, bufferConfig config.StreamBuffer) *Stream {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream := &Stream{
		policyMask: policyMask,
		events:     make(chan trace.Event, bufferConfig.Size),
	}

	if bufferConfig.Mode == "" || bufferConfig.Mode == config.StreamBufferBlock {
		stream.publish = stream.blockPublish
	} else {
		stream.publish = stream.dropPublish
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
