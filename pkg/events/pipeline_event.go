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
func (pe *PipelineEvent) Reset() {
	if pe == nil {
		return
	}
	pe.EventID = 0
	pe.Timestamp = 0
	pe.MatchedPoliciesBitmap = 0
	pe.ProtoEvent = nil
}

// ToProto converts the PipelineEvent to a v1beta1.Event for external API use.
// The conversion is cached on first call and reused thereafter to avoid redundant conversions.
// Returns nil if the conversion fails.
// Note: This uses ConvertToProto which does NOT translate event IDs - translation should
// only be applied at the gRPC boundary.
func (pe *PipelineEvent) ToProto() *pb.Event {
	if pe == nil {
		return nil
	}
	// Proto-native events have cached proto but no trace.Event
	if pe.Event == nil {
		return pe.ProtoEvent
	}
	// Lazy conversion for trace.Event-based events
	if pe.ProtoEvent == nil {
		pe.ProtoEvent = ConvertToProto(pe.Event)
	}
	return pe.ProtoEvent
}

// ToProtocol converts the PipelineEvent to a protocol.Event for the signature engine.
// This wraps the embedded trace.Event's ToProtocol method.
func (pe *PipelineEvent) ToProtocol() protocol.Event {
	if pe == nil || pe.Event == nil {
		return protocol.Event{}
	}
	return pe.Event.ToProtocol()
}
