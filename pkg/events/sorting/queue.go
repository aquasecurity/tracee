package sorting

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

type eventNode struct {
	event       *trace.Event
	previous    *eventNode
	next        *eventNode
	isAllocated bool
}

// A double linked list used to store events in LIFO order
type eventsQueue struct {
	pool  eventsPool
	tail  *eventNode
	head  *eventNode
	mutex sync.Mutex
}

// Put insert new event to the double linked list
func (eq *eventsQueue) Put(newEvent *trace.Event) error {
	newNode, err := eq.pool.Alloc(newEvent)
	if err != nil {
		eq.pool.Reset()
	}
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	eq.put(newNode)
	return errfmt.WrapError(err)
}

// Get remove the node at the head of the queue and return it
// Might return error with a valid event in case of internal pool error, for the user to know that an error occurred
// but was contained
func (eq *eventsQueue) Get() (*trace.Event, error) {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	if eq.head == nil {
		if eq.tail != nil {
			return nil, errfmt.Errorf("bug: TAIL without a HEAD")
		}
		return nil, nil
	}
	headNode := eq.head
	if headNode == eq.tail {
		if headNode.next != nil || headNode.previous != nil {
			return nil, errfmt.Errorf("bug: last existing node still connected")
		}
		eq.tail = nil
		eq.head = nil
	} else {
		if headNode.previous == nil {
			return nil, errfmt.Errorf("bug: not TAIL lacking previous")
		}
		if headNode.next != nil {
			return nil, errfmt.Errorf("bug: HEAD has next")
		}
		headNode.previous.next = nil
		eq.head = headNode.previous
	}
	headNode.previous = nil
	headNode.next = nil
	extractedEvent := headNode.event
	err := eq.pool.Free(headNode)
	if err != nil {
		eq.pool.Reset()
		return extractedEvent, errfmt.Errorf("error in queue's node freeing - %v", err)
	}
	return extractedEvent, nil
}

func (eq *eventsQueue) PeekHead() *trace.Event {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	if eq.head == nil {
		return nil
	}
	return eq.head.event
}

func (eq *eventsQueue) PeekTail() *trace.Event {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	if eq.tail == nil {
		return nil
	}
	return eq.tail.event
}

func (eq *eventsQueue) Empty() {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	eq.head = nil
	eq.tail = nil
}

// Put insert new event to the double linked list
func (eq *eventsQueue) put(newNode *eventNode) {
	if eq.tail != nil {
		newNode.next = eq.tail
		eq.tail.previous = newNode
	}
	if eq.head == nil {
		eq.head = newNode
	}
	eq.tail = newNode
}
