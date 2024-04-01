package sorting

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/pipeline"
)

type dataNode struct {
	data        *pipeline.Data
	previous    *dataNode
	next        *dataNode
	isAllocated bool
}

// A double linked list used to store events in LIFO order
type dataQueue struct {
	pool  dataPool
	tail  *dataNode
	head  *dataNode
	mutex sync.Mutex
}

// Put insert new event to the double linked list
func (eq *dataQueue) Put(newEvent *pipeline.Data) error {
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
func (eq *dataQueue) Get() (*pipeline.Data, error) {
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
	extractedEvent := headNode.data
	err := eq.pool.Free(headNode)
	if err != nil {
		eq.pool.Reset()
		return extractedEvent, errfmt.Errorf("error in queue's node freeing - %v", err)
	}
	return extractedEvent, nil
}

func (eq *dataQueue) PeekHead() *pipeline.Data {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	if eq.head == nil {
		return nil
	}
	return eq.head.data
}

func (eq *dataQueue) PeekTail() *pipeline.Data {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	if eq.tail == nil {
		return nil
	}
	return eq.tail.data
}

func (eq *dataQueue) Empty() {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	eq.head = nil
	eq.tail = nil
}

// Put insert new event to the double linked list
func (eq *dataQueue) put(newNode *dataNode) {
	if eq.tail != nil {
		newNode.next = eq.tail
		eq.tail.previous = newNode
	}
	if eq.head == nil {
		eq.head = newNode
	}
	eq.tail = newNode
}
