package events

// EventFlags defines an interface for accessing the flags of a single event in a read-only manner.
type EventFlags interface {
	// GetSubmit returns the submit flag of the event.
	GetSubmit() uint64

	// GetEmit returns the emit flag of the event.
	GetEmit() uint64

	// ShouldSubmit returns true if the event is marked to be submitted.
	ShouldSubmit() bool

	// ShouldEmit returns true if the event is marked to be emitted.
	ShouldEmit() bool

	// RequiredBySignature returns true if the event is required by a signature.
	RequiredBySignature() bool
}

// EventsFlags defines an interface for accessing a collection of event flags in a read-only manner.
// It allows for querying individual events or collections of events.
type EventsFlags interface {
	// Get returns the event flags of the given event ID.
	Get(ID) EventFlags

	// GetOk returns the event flags of the given event ID and a boolean indicating if the event ID exists.
	GetOk(ID) (EventFlags, bool)

	// GetAll returns a map of all event flags.
	GetAll() map[ID]EventFlags

	// GetAllCancelled returns a slice of all event IDs that are marked as cancelled.
	GetAllCancelled() []ID
}
