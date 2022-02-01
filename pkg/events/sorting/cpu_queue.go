package sorting

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/external"
)

// Events queue with the ability to follow if it was updated since last check and insertion by time specific for CPU
// queue ordering
type cpuEventsQueue struct {
	eventsQueue
	IsUpdated bool
}

// InsertByTimestamp insert new event to the queue in the right position according to its timestamp
func (cq *cpuEventsQueue) InsertByTimestamp(newEvent *external.Event) error {
	newNode := cq.pool.Alloc(newEvent)

	cq.mutex.Lock()
	defer cq.mutex.Unlock()
	if cq.tail != nil &&
		cq.tail.event.Timestamp > newEvent.Timestamp {
		// We have a fresh event with a timestamp older than the last event received in this cpu's queue.
		// This can only happen if this fresh event is a syscall event (for which we take the entry timestamp) which
		// called some internal kernel functions (that are also traced). Insert the syscall event before these other
		// events
		insertLocation := cq.tail
		for insertLocation.next != nil {
			if insertLocation.next.event.Timestamp < newEvent.Timestamp {
				break
			}
			if insertLocation.next == insertLocation {
				return fmt.Errorf("encountered node with self reference at next")
			}
			insertLocation = insertLocation.next
		}
		cq.insertAfter(newNode, insertLocation)
	} else {
		cq.put(newNode)
	}
	return nil
}

// insertAfter insert new event to the queue after another node
// This is useful if new node place is not at the end of the queue but before it
func (cq *cpuEventsQueue) insertAfter(newNode *eventNode, baseEvent *eventNode) {
	if baseEvent.next != nil {
		baseEvent.next.previous = newNode
	}
	newNode.previous = baseEvent
	newNode.next, baseEvent.next = baseEvent.next, newNode
	if cq.head == baseEvent {
		cq.head = newNode
	}
}
