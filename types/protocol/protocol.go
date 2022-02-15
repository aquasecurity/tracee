package protocol

//EventHeaders are headers attached to the Event struct, used to send metadata about the payload
type EventHeaders struct {
	// ContentType indicates the content of the Event payload.
	ContentType string
	// Origin indicates whether Event originates from host or container.
	Origin string
	// Custom additional custom headers, nil most of the time
	Custom map[string]string
}

//Event is a generic event that the Engine can process
type Event struct {
	Headers EventHeaders
	Payload interface{}
}

func (e Event) ContentType() string {
	return e.Headers.ContentType
}

func (e Event) Origin() string {
	return e.Headers.Origin
}

func (e Event) Header(header string) string {
	if e.Headers.Custom != nil {
		return e.Headers.Custom[header]
	}
	return ""
}
