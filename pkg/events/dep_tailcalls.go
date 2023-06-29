package events

//
// Dependencies: TailCalls
//

// SetTailCalls sets the tailCalls to a new given set (thread-safe).
func (d *Dependencies) SetTailCalls(givenTcs []*TailCall) {
	d.tailCallsLock.Lock()
	defer d.tailCallsLock.Unlock()

	// delete all previous tailCalls
	for k := range d.tailCalls {
		delete(d.tailCalls, k)
	}

	d.addTailCalls(givenTcs)
}

// GetTailCalls returns a slice copy of instanced tailCalls (thread-safe).
func (d *Dependencies) GetTailCalls() []*TailCall {
	d.tailCallsLock.RLock()
	defer d.tailCallsLock.RUnlock()

	a := []*TailCall{}
	for _, v := range d.tailCalls {
		for _, t := range v {
			a = append(a, t)
		}
	}

	return a
}

// AddTailCall adds a tailCall dependency to the event (thread-safe).
func (d *Dependencies) AddTailCall(givenTc *TailCall) {
	d.tailCallsLock.Lock()
	defer d.tailCallsLock.Unlock()
	d.addTailCalls([]*TailCall{givenTc})
}

// AddTailCalls adds tailCalls dependencies to the event (thread-safe).
func (d *Dependencies) AddTailCalls(givenTcs []*TailCall) {
	d.tailCallsLock.Lock()
	defer d.tailCallsLock.Unlock()
	d.addTailCalls(givenTcs)
}

// DelTailCalls removes tailCalls dependencies from the event (thread-safe).
func (d *Dependencies) GetTailCallsByMapName(mapName string) []*TailCall {
	d.tailCallsLock.RLock()
	defer d.tailCallsLock.RUnlock()

	a := []*TailCall{}
	for _, v := range d.tailCalls[mapName] {
		a = append(a, v)
	}

	return a
}

// GetTailCallByMapAndProgName returns a tailCall dependency by map and prog name (thread-safe).
func (d *Dependencies) GetTailCallByMapAndProgName(mapName, progName string) *TailCall {
	d.tailCallsLock.RLock()
	defer d.tailCallsLock.RUnlock()
	return d.tailCalls[mapName][progName]
}

// DelTailCallsByMapNames removes tailCalls dependencies from the event by given map (thread-safe).
func (d *Dependencies) DelTailCallsByMapNames(mapNames []string) {
	d.tailCallsLock.Lock()
	defer d.tailCallsLock.Unlock()

	for _, mapName := range mapNames {
		delete(d.tailCalls, mapName)
	}
}

// DelTailCallByMapAndProgName removes it from the event by given map and prog name (thread-safe).
func (d *Dependencies) DelTailCallByMapAndProgName(mapName, progName string) {
	d.tailCallsLock.Lock()
	defer d.tailCallsLock.Unlock()
	delete(d.tailCalls[mapName], progName)
}

// addTailCalls adds tailCalls dependencies to the event (no locking).
func (d *Dependencies) addTailCalls(givenTcs []*TailCall) {
	for _, tc := range givenTcs {
		if _, ok := d.tailCalls[tc.mapName]; !ok {
			d.tailCalls[tc.mapName] = make(map[string]*TailCall)
		}

		d.tailCalls[tc.mapName][tc.progName] = tc
	}
}
