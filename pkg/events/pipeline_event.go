package events

import (
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// PipelineEvent is an internal event structure used throughout the pipeline.
// It embeds the external types.Event for user-facing data and adds internal
// fields needed for pipeline processing that should not be exposed to end users.
type PipelineEvent struct {
	// User-facing event data
	*trace.Event

	// Internal pipeline fields
	// MatchedPoliciesBitmap is a combined bitmap for efficient policy matching.
	// This replaces the need to expose separate Kernel/User bitmaps to external APIs.
	MatchedPoliciesBitmap uint64
}

// NewPipelineEvent creates a new PipelineEvent wrapping the provided trace.Event.
// The MatchedPoliciesBitmap is initialized from the event's MatchedPoliciesKernel field.
func NewPipelineEvent(event *trace.Event) *PipelineEvent {
	if event == nil {
		return nil
	}
	return &PipelineEvent{
		Event:                 event,
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
	pe.MatchedPoliciesBitmap = 0
}

// ToProtocol converts the PipelineEvent to a protocol.Event for the signature engine.
// This wraps the embedded trace.Event's ToProtocol method.
func (pe *PipelineEvent) ToProtocol() protocol.Event {
	if pe == nil || pe.Event == nil {
		return protocol.Event{}
	}
	return pe.Event.ToProtocol()
}
