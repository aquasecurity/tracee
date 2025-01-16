package proctree

import (
	"sync"
	"sync/atomic"
)

//
// Process
//

// Process represents a process.
type Process struct {
	processHash uint32              // hash of process (immutable, so no need of concurrency control)
	parentHash  uint32              // hash of parent
	info        *TaskInfo           // task info (immutable pointer)
	executable  *FileInfo           // executable info (immutable pointer)
	children    map[uint32]struct{} // hash of children
	threads     map[uint32]struct{} // hash of threads
	// Control fields
	mutex *sync.RWMutex // mutex to protect the process
}

// NewProcess creates a new thread with an initialized task info.
func NewProcess(hash uint32, info *TaskInfo) *Process {
	return &Process{
		processHash: hash,
		parentHash:  0,
		info:        info,
		executable:  NewFileInfo(),
		children:    make(map[uint32]struct{}),
		threads:     make(map[uint32]struct{}),
		mutex:       &sync.RWMutex{},
	}
}

// Getters

// GetHash returns the hash of the process.
func (p *Process) GetHash() uint32 {
	return p.processHash // immutable
}

// GetParentHash returns the hash of the parent.
func (p *Process) GetParentHash() uint32 {
	return atomic.LoadUint32(&p.parentHash)
}

// GetInfo returns a instanced task info.
func (p *Process) GetInfo() *TaskInfo {
	return p.info // immutable pointer
}

// GetExecutable returns a instanced executable info.
func (p *Process) GetExecutable() *FileInfo {
	return p.executable // immutable pointer
}

// Setters

// SetParentHash sets the hash of the parent.
func (p *Process) SetParentHash(parentHash uint32) {
	atomic.StoreUint32(&p.parentHash, parentHash)
}

//
// Children and Threads
//

// AddChild adds a child to the process.
func (p *Process) AddChild(childHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.children[childHash] = struct{}{}
}

// AddThread adds a thread to the process.
func (p *Process) AddThread(threadHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.threads[threadHash] = struct{}{}
}

// GetChildren returns the children of the process.
func (p *Process) GetChildren() []uint32 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	children := make([]uint32, 0, len(p.children))
	for child := range p.children {
		children = append(children, child)
	}

	return children
}

// GetThreads returns the threads of the process.
func (p *Process) GetThreads() []uint32 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	threads := make([]uint32, 0, len(p.threads))
	for thread := range p.threads {
		threads = append(threads, thread)
	}

	return threads
}

// DelChild deletes a child from the process.
func (p *Process) DelChild(childHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	delete(p.children, childHash)
}

// DelThread deletes a thread from the process.
func (p *Process) DelThread(threadHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	delete(p.threads, threadHash)
}
