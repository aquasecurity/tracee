package streams

import (
	"context"
	"sync"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
)

// Stream is a stream of events
type Stream struct {
	// policy mask is a bitmap of policies that this stream is interested in
	policyMask uint64
	// event to filter
	eventMap map[int32]struct{}
	// true if there is at least one element in the eventMap
	eventFilter bool
	// events is a channel that is used to receive events from the stream
	events       chan *pb.Event
	strategyPush func(context.Context, *pb.Event)
}

// ReceiveEvents returns a read-only channel for receiving events from the stream
func (s *Stream) ReceiveEvents() <-chan *pb.Event {
	return s.events
}

// Publish publishes an event to the stream,
// but first check if this stream is interested in this event,
// by checking the event's policy mask against the stream's policy mask.
func (s *Stream) publish(ctx context.Context, event *pb.Event, policyBitmap uint64) {
	if s.shouldIgnorePolicy(policyBitmap) {
		return
	}

	if s.eventFilter {
		if _, ok := s.eventMap[int32(event.Id)]; !ok {
			return
		}
	}

	// Due to the dynamic nature of this function the compiler doesn't
	// inline this. A condition is faster (and cheaper) than a function call
	// should we change it with a condition?
	s.strategyPush(ctx, event)
}

// blockPublish publishes an event to the stream, blocking if the channel is full.
func (s *Stream) blockPublish(ctx context.Context, event *pb.Event) {
	select {
	case s.events <- event:
	case <-ctx.Done():
		return
	}
}

// dropPublish publishes an event to the stream, dropping the event if the channel is full.
func (s *Stream) dropPublish(ctx context.Context, event *pb.Event) {
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
func (s *Stream) shouldIgnorePolicy(policyBitmap uint64) bool {
	return s.policyMask&policyBitmap == 0
}

// close closes the stream
func (s *Stream) close() {
	close(s.events)
}

// StreamManager manages streams
type StreamsManager struct {
	mutex       sync.RWMutex
	subscribers map[*Stream]struct{}
}

// NewStreamManager creates a new stream manager
func NewStreamsManager() *StreamsManager {
	return &StreamsManager{
		mutex:       sync.RWMutex{},
		subscribers: make(map[*Stream]struct{}),
	}
}

// Subscribe adds a stream to the manager
func (sm *StreamsManager) Subscribe(policyMask uint64, eventMap map[int32]struct{}, bufferConfig config.StreamBuffer) *Stream {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream := &Stream{
		policyMask:  policyMask,
		events:      make(chan *pb.Event, bufferConfig.Size),
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

// Publish publishes an event to all streams.
// The event is a pb.Event pointer and the policyBitmap indicates which policies matched.
func (sm *StreamsManager) Publish(ctx context.Context, event *pb.Event, policyBitmap uint64) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	for stream := range sm.subscribers {
		stream.publish(ctx, event, policyBitmap)
	}
}

// HasSubscribers returns true if there are any active subscribers
func (sm *StreamsManager) HasSubscribers() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return len(sm.subscribers) > 0
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
