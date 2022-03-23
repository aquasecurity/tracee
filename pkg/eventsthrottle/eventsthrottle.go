package eventsthrottle

import "sync"

type EventsChange struct {
	AffectedEvents   []int
	AreEventsDropped bool
}

type LoadChange struct {
	ChangeInEvents EventsChange
}

type EventsThrottlingState struct {
	currentEventPriorityThreshold int
	maxPriorityThreshold          int
	minPriorityThreshold          int
	mtx                           sync.RWMutex
}

func NewEventsThrottlingState() EventsThrottlingState {
	return EventsThrottlingState{
		currentEventPriorityThreshold: 0,
		maxPriorityThreshold:          4,
		minPriorityThreshold:          0,
		mtx:                           sync.RWMutex{},
	}
}

func (hp *EventsThrottlingState) DecreasePriorityThreshold() {
	hp.mtx.Lock()
	defer hp.mtx.Unlock()
	if hp.currentEventPriorityThreshold >= hp.minPriorityThreshold {
		hp.currentEventPriorityThreshold--
	}
}

func (hp *EventsThrottlingState) IncreasePriorityThreshold() {
	hp.mtx.Lock()
	defer hp.mtx.Unlock()
	if hp.currentEventPriorityThreshold <= hp.maxPriorityThreshold {
		hp.currentEventPriorityThreshold++
	}
}

func (hp *EventsThrottlingState) PriorityThreshold() int {
	hp.mtx.RLock()
	defer hp.mtx.RUnlock()
	return hp.currentEventPriorityThreshold
}

func (hp *EventsThrottlingState) MaxPriorityThreshold() int {
	return hp.maxPriorityThreshold
}

func (hp *EventsThrottlingState) MinPriorityThreshold() int {
	return hp.minPriorityThreshold
}
