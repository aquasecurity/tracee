// Package protocol includes the "API" of events the rule-engine can consume. All producers who intend to add support for tracee need to support this protocol.
package protocol

// EventHeaders are headers attached to the Event struct, used to send metadata about the payload
type EventHeaders struct {
	// Selector is a propriotary header used for filtering event subscriptions in the engin
	Selector Selector

	// Custom additional custom headers, nil most of the time
	custom map[string]string
}

// Selector is a propriotary header used for filtering event subscriptions in the engine
type Selector struct {
	// Name indicates the name of the Event payload
	Name string
	// Origin indicates where the event was generated (host, container, pod), this may be empty depending on Source
	Origin string
	// Source indicates the producer of the Event (example: tracee, CNDR, K8SAuditLog...)
	Source string
}

// Event is a generic event that the Engine can process
type Event struct {
	Headers EventHeaders
	Payload interface{}
}

// Get Event's Selector
func (e *Event) Selector() Selector {
	return e.Headers.Selector
}

// Get a custom header that was set through SetHeader
func (e *Event) Header(header string) string {
	if e.Headers.custom != nil {
		return e.Headers.custom[header]
	}
	return ""
}

// Set a custom header
func (e *Event) SetHeader(header string, value string) {
	if e.Headers.custom == nil {
		e.Headers.custom = make(map[string]string)
	}
	e.Headers.custom[header] = value
}
