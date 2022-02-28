package protocol

//EventHeaders are headers attached to the Event struct, used to send metadata about the payload
type EventHeaders struct {
	// ContentType indicates the content of the Event payload.
	ContentType string
	// Origin indicates whether Event originates from host or container.
	Origin string
	// Custom additional custom headers, nil most of the time
	custom map[string]string
}

//Event is a generic event that the Engine can process
type Event struct {
	Headers EventHeaders
	Payload interface{}
}

func (e *Event) ContentType() string {
	return e.Headers.ContentType
}

func (e *Event) Origin() string {
	return e.Headers.Origin
}

func (e *Event) Header(header string) string {
	if e.Headers.custom != nil {
		return e.Headers.custom[header]
	}
	return ""
}

func (e *Event) SetHeader(header string, value string) {
	if e.Headers.custom == nil {
		e.Headers.custom = make(map[string]string)
	}
	e.Headers.custom[header] = value
}
