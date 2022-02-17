package queue

import (
	"container/list"
	"fmt"
	"github.com/aquasecurity/tracee/types/trace"
	"sync"
)

type EventQueueMem struct {
	mutex                *sync.Mutex
	cond                 *sync.Cond
	cache                *list.List
	maxAmountOfEvents    int // max number of cached events possible
	EventsCacheMemSizeMB int
}

func (q *EventQueueMem) String() string {
	return fmt.Sprintf("In-Memory Event Queue (Size = %d MB)", q.EventsCacheMemSizeMB)
}

func (q *EventQueueMem) Setup() error {
	q.mutex = new(sync.Mutex)
	q.cond = sync.NewCond(q.mutex)

	// set queue size and init queue
	q.maxAmountOfEvents = q.getQueueSizeInEvents()
	q.cache = new(list.List)

	return nil
}

// Enqueue pushes an event into the queue (may block until queue is available)
func (q *EventQueueMem) Enqueue(evt *trace.Event) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	// enqueue waits for de-queuing if cache is full
	for q.cache.Len() == q.maxAmountOfEvents {
		q.cond.Wait()
	}

	q.cache.PushBack(*evt)
	q.cond.Signal() // unblock dequeue if needed

	evt = nil
}

// Dequeue pops an event from the queue
func (q *EventQueueMem) Dequeue() *trace.Event {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	// dequeue waits for en-queueing if cache is empty
	for q.cache.Len() == 0 {
		q.cond.Wait()
	}

	e := q.cache.Front()
	event, ok := e.Value.(trace.Event)
	if !ok {
		return nil
	}
	q.cache.Remove(e)
	q.cond.Signal() // unblock enqueue if needed

	return &event
}

// getQueueSizeInEvents returns size of the fifo queue, in # of events, based on
// the host size
func (q *EventQueueMem) getQueueSizeInEvents() int {
	// eventSize is the memory footprint per event, in bytes. This is NOT the
	// size of a single event, but the overall impact in memory consumption to
	// each cached event (defined by experimentation)
	eventSize := 1024

	KBtoB := func(amountInKB int) int {
		return amountInKB * 1024
	}
	MBtoKB := func(amountInMB int) int {
		return amountInMB * 1024
	}
	GBtoMB := func(amountInGB int) int {
		return amountInGB * 1024
	}
	AmountOfEvents := func(amountInMB int) int {
		return MBtoKB(KBtoB(amountInMB)) / eventSize
	}

	// EventsCacheMemSize was provided, return exact amount of events for it
	if q.EventsCacheMemSizeMB > 0 {
		return AmountOfEvents(q.EventsCacheMemSizeMB)

	}

	switch {
	case q.EventsCacheMemSizeMB <= GBtoMB(1): // up to 1GB, cache = ~256MB in events #
		return AmountOfEvents(256)
	case q.EventsCacheMemSizeMB <= GBtoMB(4): // up to 4GB, cache = ~512MB in events #
		return AmountOfEvents(512)
	case q.EventsCacheMemSizeMB <= GBtoMB(8): // up to 8GB, cache = ~1GB in events #
		return AmountOfEvents(GBtoMB(1))
	case q.EventsCacheMemSizeMB <= GBtoMB(16): // up to 16GB, cache = ~2GB in events #
		return AmountOfEvents(GBtoMB(2))
	}

	// bigger hosts, cache = ~4GB in events #
	return AmountOfEvents(GBtoMB(4))
}
