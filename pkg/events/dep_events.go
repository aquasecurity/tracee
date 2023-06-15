package events

//
// Dependencies: Events
//

// SetEvents sets the event to a new given set (thread-safe).
func (d *Dependencies) SetEvents(events []ID) {
	d.eventsLock.Lock()
	defer d.eventsLock.Unlock()

	// delete all previous events
	for k := range d.events {
		delete(d.events, k)
	}

	d.addEvents(events)
}

// GetEvents returns a slice copy of instanced events (thread-safe).
func (d *Dependencies) GetEvents() []ID {
	d.eventsLock.RLock()
	defer d.eventsLock.RUnlock()

	a := []ID{}
	for k := range d.events {
		a = append(a, k)
	}

	return a
}

// AddEvent adds an event dependency to the event (thread-safe).
func (d *Dependencies) AddEvent(event ID) {
	d.eventsLock.Lock()
	defer d.eventsLock.Unlock()

	d.events[event] = struct{}{}
}

// AddEvents adds events dependencies to the event (thread-safe).
func (d *Dependencies) AddEvents(events []ID) {
	d.eventsLock.Lock()
	defer d.eventsLock.Unlock()

	d.addEvents(events)
}

// DelEvents removes events dependencies from the event (thread-safe).
func (d *Dependencies) DelEvents(events []ID) {
	d.eventsLock.Lock()
	defer d.eventsLock.Unlock()

	for _, e := range events {
		delete(d.events, e)
	}
}

// DelEvent removes an event dependency from the event (thread-safe).
func (d *Dependencies) DelEvent(event ID) {
	d.eventsLock.Lock()
	defer d.eventsLock.Unlock()

	delete(d.events, event)
}

// addEvents adds events dependencies to the event (no locking).
func (d *Dependencies) addEvents(events []ID) {
	for _, e := range events {
		d.events[e] = struct{}{}
	}
}
