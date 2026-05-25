package events

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// PipelineEvent is an internal event structure used throughout the pipeline.
// It embeds the external types.Event for user-facing data and adds internal
// fields needed for pipeline processing that should not be exposed to end users.
type PipelineEvent struct {
	// User-facing event data
	*trace.Event

	// Internal pipeline metadata
	// EventID is the original internal event ID (before translation to external format).
	EventID ID

	// Timestamp is the original event timestamp in nanoseconds since epoch.
	Timestamp uint64

	// MatchedPoliciesBitmap is a combined bitmap for efficient policy matching.
	// This replaces the need to expose separate Kernel/User bitmaps to external APIs.
	MatchedPoliciesBitmap uint64

	// ProtoEvent is a cached protobuf representation of the event.
	// It is lazily populated on first call to ToProto() and reused thereafter.
	// For proto-native detector events, this is set directly without a trace.Event.
	ProtoEvent *pb.Event

	// protoSlab holds the pooled slab backing ProtoEvent for trace.Event-based
	// events. Reset returns it to protoSlabPool; DetachProto clears it so the
	// slab escapes (and is GC'd when callers drop their references) instead of
	// being recycled while a stream still holds the proto.
	protoSlab *eventSlab
}

// NewPipelineEvent creates a new PipelineEvent wrapping the provided trace.Event.
// The MatchedPoliciesBitmap is initialized from the event's MatchedPoliciesKernel field.
// The EventID and Timestamp are copied to top-level fields for efficient pipeline access.
func NewPipelineEvent(event *trace.Event) *PipelineEvent {
	if event == nil {
		return nil
	}
	return &PipelineEvent{
		Event:                 event,
		EventID:               ID(event.EventID),
		Timestamp:             uint64(event.Timestamp),
		MatchedPoliciesBitmap: event.MatchedPoliciesKernel,
	}
}

// ToTraceEvent returns the embedded trace.Event for external API use.
// This method allows extracting the user-facing event data when needed.
func (pe *PipelineEvent) ToTraceEvent() *trace.Event {
	if pe == nil {
		return nil
	}
	return pe.Event
}

// Reset resets the internal fields of PipelineEvent for pool reuse.
// The embedded Event pointer is not reset here as it will be replaced
// when getting a new event from the pool.
// If a proto slab is still attached (event was filtered, not published),
// it is returned to protoSlabPool for reuse.
func (pe *PipelineEvent) Reset() {
	if pe == nil {
		return
	}
	pe.EventID = 0
	pe.Timestamp = 0
	pe.MatchedPoliciesBitmap = 0
	if pe.protoSlab != nil {
		protoSlabPool.Put(pe.protoSlab)
		pe.protoSlab = nil
	}
	pe.ProtoEvent = nil
}

// ToProto converts the PipelineEvent to a v1beta1.Event for external API use.
// The conversion is cached on first call and reused thereafter to avoid redundant conversions.
// Returns nil if the conversion fails.
// Note: This does NOT translate event IDs - translation should only be applied
// at the gRPC boundary.
func (pe *PipelineEvent) ToProto() *pb.Event {
	if pe == nil {
		return nil
	}
	// Proto-native events have cached proto but no trace.Event
	if pe.Event == nil {
		return pe.ProtoEvent
	}
	// Lazy conversion for trace.Event-based events: acquire a slab from the
	// pool and fill it. The slab is returned to the pool on Reset, or escapes
	// via DetachProto when the proto is published to a stream.
	if pe.ProtoEvent == nil {
		s := protoSlabPool.Get().(*eventSlab)
		s.reset()
		pe.protoSlab = s
		pe.ProtoEvent = fillProtoSlab(pe.Event, s)
	}
	return pe.ProtoEvent
}

// DetachProto releases the proto event from this PipelineEvent and removes the
// backing slab from pool management. Callers (typically the sink stage before
// publishing to a stream subscriber) take ownership of the returned proto and
// of any sub-objects in the slab; the slab will be garbage-collected when no
// references remain.
func (pe *PipelineEvent) DetachProto() *pb.Event {
	if pe == nil {
		return nil
	}
	pe.protoSlab = nil // prevent Reset from returning the slab to the pool
	proto := pe.ProtoEvent
	pe.ProtoEvent = nil
	return proto
}

// ToProtocol converts the PipelineEvent to a protocol.Event for the signature engine.
// This wraps the embedded trace.Event's ToProtocol method.
func (pe *PipelineEvent) ToProtocol() protocol.Event {
	if pe == nil || pe.Event == nil {
		return protocol.Event{}
	}
	return pe.Event.ToProtocol()
}
