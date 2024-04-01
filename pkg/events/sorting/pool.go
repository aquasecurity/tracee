package sorting

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/pipeline"
)

const poolFreeingPart = 2
const minPoolFreeingSize = 200

// dataPool is a struct used to store empty eventNodes to prevent repeated allocation and freeing from the heap.
// In details, the struct envelopes the allocation and freeing of the eventNode object, and store freed nodes
// to to use them again when new allocation is required.
// Pool is a known mechanism, so you can read more on it online.
type dataPool struct {
	head             *dataNode
	poolMutex        sync.Mutex
	allocationsCount int
	poolSize         int
}

// Alloc return an eventNode that contains the event given.
// The function will try to use stored eventNode if there is one available.
// If there isn't, it will allocate new one.
func (p *dataPool) Alloc(event *pipeline.Data) (*dataNode, error) {
	p.poolMutex.Lock()
	p.allocationsCount++
	node := p.head
	if node != nil {
		if node.isAllocated {
			p.poolMutex.Unlock()
			return &dataNode{data: event, isAllocated: true}, errfmt.Errorf("bug: alocated node in pool")
		}
		p.head = node.previous
		node.data = event
		node.isAllocated = true
		node.previous = nil
		node.next = nil
		p.poolSize--
		p.poolMutex.Unlock()
		return node, nil
	}
	p.poolMutex.Unlock()
	return &dataNode{data: event, isAllocated: true}, nil
}

// Free handle the eventNode after its usage has ended.
// Free will try to store the node in the pool to be used by a future Alloc call.
// To prevent the storage of all nodes event when there is no use for them (like after peaks of allocations), whenever
// the amount of stored nodes pass the amount of nodes in use, a part of the pool will be removed from the pool (and
// as a result will be garbage collected).
func (p *dataPool) Free(node *dataNode) error {
	p.poolMutex.Lock()
	defer p.poolMutex.Unlock()
	// Prevent malicious use of free
	if p.allocationsCount == 0 {
		return errfmt.Errorf("bug: free called when no allocated node exist")
	}

	node.isAllocated = false
	node.previous = nil
	node.next = nil
	p.allocationsCount--
	// Free memory in case of pooling too many nodes
	if p.poolSize >= p.allocationsCount &&
		p.poolSize >= minPoolFreeingSize {
		freeingAmount := p.poolSize / poolFreeingPart
		for i := 0; i < freeingAmount; i++ {
			p.head = p.head.previous
		}
		p.poolSize -= freeingAmount
	} else { // Add unused node to pool
		if p.head == nil {
			p.head = node
		} else {
			node.previous = p.head
			p.head.next = node
			p.head = node
		}
		p.poolSize++
	}
	return nil
}

func (p *dataPool) Reset() {
	p.poolMutex.Lock()
	defer p.poolMutex.Unlock()
	node := p.head
	for node != nil {
		next := node.previous
		node.next = nil
		node.previous = nil
		node = next
	}
	p.allocationsCount = 0
	p.poolSize = 0
}
