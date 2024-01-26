package extensions

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	allPolicies = ^uint64(0)
	noPolicies  = 0
)

//
// All States
//

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

func (s *StatesPerExtension) Create(ext string, id int) *EventState {
	return s.GetOrCreate(ext, id)
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

//
// EventState
//

type EventState struct {
	submit uint64 // should be submitted to user space (by policies bitmap)
	emit   uint64 // should be emitted to the user (by policies bitmap)
	mutex  *sync.RWMutex
}

func (es *EventState) SetSubmitForPolicy(id int) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	utils.SetBit(&es.submit, uint(id))
}

func (es *EventState) SetEmitForPolicy(id int) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	utils.SetBit(&es.emit, uint(id))
}

func (es *EventState) UnsetSubmitForPolicy(id int) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	utils.ClearBit(&es.submit, uint(id))
}

func (es *EventState) UnsetEmitForPolicy(id int) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	utils.ClearBit(&es.emit, uint(id))
}

func (es *EventState) SetSubmitAll() {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.submit = allPolicies
}

func (es *EventState) SetEmitAll() {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.emit = allPolicies
}

func (es *EventState) UnsetSubmitAll() {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.submit = 0
}

func (es *EventState) UnsetEmitAll() {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	es.emit = 0
}

func (es *EventState) AnySubmitEnabled() bool {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return es.submit != 0
}

func (es *EventState) AnyEmitEnabled() bool {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return es.emit != 0
}

func (es *EventState) IsSubmitEnabledForPolicy(id int) bool {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return utils.HasBit(es.submit, uint(id))
}

func (es *EventState) IsEmitEnabledForPolicy(id int) bool {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return utils.HasBit(es.emit, uint(id))
}

func (es *EventState) CloneSubmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit = givenState.submit
}

func (es *EventState) CloneEmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.emit = givenState.emit
}

func (es *EventState) CloneFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit = givenState.submit
	es.emit = givenState.emit
}

func (es *EventState) OrSubmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit |= givenState.submit
}

func (es *EventState) OrEmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.emit |= givenState.emit
}

func (es *EventState) OrFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit |= givenState.submit
	es.emit |= givenState.emit
}

func (es *EventState) AndSubmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit &= givenState.submit
}

func (es *EventState) AndEmitFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.emit &= givenState.emit
}

func (es *EventState) AndFrom(givenState *EventState) {
	es.mutex.Lock()
	defer es.mutex.Unlock()
	givenState.mutex.RLock()
	defer givenState.mutex.RUnlock()
	es.submit &= givenState.submit
	es.emit &= givenState.emit
}

func (es *EventState) GetSubmitCopy() uint64 {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return es.submit
}

func (es *EventState) GetEmitCopy() uint64 {
	es.mutex.RLock()
	defer es.mutex.RUnlock()
	return es.emit
}
