package extensions

import (
	"sync"
)

const (
	allPolicies = ^uint64(0)
	noPolicies  = 0
)

type StatesPerExtension struct {
	states map[string]map[int]*EventState // [extension_name][event_id]event_state
	mutex  *sync.RWMutex
}

// Get returns the EventState for the given extension and event ID (might be nil).
func (s *StatesPerExtension) Get(ext string, id int) *EventState {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if _, ok := s.states[ext]; !ok {
		return nil
	}
	return s.states[ext][id]
}

// GetOk returns the EventState for the given extension and event ID (preferable).
func (s *StatesPerExtension) GetOk(ext string, id int) (*EventState, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if _, ok := s.states[ext]; !ok {
		return nil, false
	}
	state, ok := s.states[ext][id]
	return state, ok
}

// GetOrCreate returns the EventState for the given extension and event ID.
func (s *StatesPerExtension) GetOrCreate(ext string, id int) *EventState {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.states[ext]; !ok {
		s.states[ext] = map[int]*EventState{}
	}
	if _, ok := s.states[ext][id]; !ok {
		s.states[ext][id] = &EventState{
			submit: noPolicies,
			emit:   noPolicies,
			mutex:  &sync.RWMutex{},
		}
	}
	return s.states[ext][id]
}

// GetEventIDs returns the event IDs for the given extension.
func (s *StatesPerExtension) GetEventIDs(ext string) []int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if _, ok := s.states[ext]; !ok {
		return []int{}
	}
	ids := []int{}
	for id := range s.states[ext] {
		ids = append(ids, id)
	}
	return ids
}

// HasEventID returns true if the given extension has the given event ID.
func (s *StatesPerExtension) HasEventID(ext string, id int) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if _, ok := s.states[ext]; !ok {
		return false
	}
	_, ok := s.states[ext][id]
	return ok
}

// Delete deletes the EventState for the given extension and event ID.
func (s *StatesPerExtension) Delete(ext string, id int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.states[ext]; !ok {
		return
	}
	delete(s.states[ext], id)
}

// DeleteAll deletes all EventStates for the given extension.
func (s *StatesPerExtension) DeleteAll(ext string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.states, ext)
}

type EventState struct {
	submit uint64 // should be submitted to user space (by policies bitmap)
	emit   uint64 // should be emitted to the user (by policies bitmap)
	mutex  *sync.RWMutex
}
