package streams

import (
	"sync"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
)

// Stream is a stream of events
type Stream struct {
	// policies is the set of policy names this stream is interested in (nil/empty = all)
	policies map[string]struct{}
	// event to filter
	eventMap map[int32]struct{}
	// true if there is at least one element in the eventMap
	eventFilter bool
	// events is a channel that is used to receive events from the stream
	events       chan *pb.Event
	strategyPush func(*pb.Event)
}

// ReceiveEvents returns a read-only channel for receiving events from the stream
func (s *Stream) ReceiveEvents() <-chan *pb.Event {
	return s.events
}

// Publish publishes an event to the stream,
// but first check if this stream is interested in this event,
// by checking the event's policy mask against the stream's policy mask.
func (s *Stream) publish(event *pb.Event, matched []string) {
	if s.shouldIgnore(matched) {
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
	s.strategyPush(event)
}

// blockPublish publishes an event to the stream, blocking if the channel is full.
// NOTE: We do NOT check ctx.Done() here anymore - we must send all events
// to ensure graceful drain during shutdown. The channel will be closed
// when the stream is unsubscribed, which properly terminates consumers.
func (s *Stream) blockPublish(event *pb.Event) {
	s.events <- event
}

// dropPublish publishes an event to the stream, dropping the event if the channel is full.
// NOTE: We do NOT check ctx.Done() here anymore - we must attempt to send all events
// to ensure graceful drain during shutdown.
func (s *Stream) dropPublish(event *pb.Event) {
	select {
	case s.events <- event:
	default:
		// Probably this is going to be too verbose
		logger.Debugw("stream channel full, dropping message")
	}
}

// shouldIgnore reports whether the stream should drop the event, given the names of the
// (user-selected) policies that matched it. A stream with no policy filter accepts all.
func (s *Stream) shouldIgnore(matched []string) bool {
	if len(s.policies) == 0 {
		return false // subscribed to all policies
	}
	for _, name := range matched {
		if _, ok := s.policies[name]; ok {
			return false // at least one matched policy is of interest
		}
	}
	return true
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
func (sm *StreamsManager) Subscribe(policies map[string]struct{}, eventMap map[int32]struct{}, bufferConfig config.StreamBuffer) *Stream {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	stream := &Stream{
		policies:    policies,
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

// Publish publishes an event to all interested streams. matched is the list of
// (user-selected) policy names that matched the event; streams filter on it by name.
func (sm *StreamsManager) Publish(event *pb.Event, matched []string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for stream := range sm.subscribers {
		stream.publish(event, matched)
	}
}

// HasSubscribers returns true if there are any active subscribers
func (sm *StreamsManager) HasSubscribers() bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
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
