package proctree

import (
	"sync"
)

//
// Process
//

// Process represents a process.
type Process struct {
	processHash uint32              // hash of process
	parentHash  uint32              // hash of parent
	info        *TaskInfo           // task info
	executable  *FileInfo           // executable info
	children    map[uint32]struct{} // hash of childrens
	threads     map[uint32]struct{} // hash of threads
	// Control fields
	mutex *sync.RWMutex // mutex to protect the process
}

// NewProcess creates a new process.
func NewProcess(hash uint32) *Process {
	return &Process{
		processHash: hash,
		parentHash:  0,
		info:        NewTaskInfo(),
		executable:  NewFileInfo(),
		children:    make(map[uint32]struct{}),
		threads:     make(map[uint32]struct{}),
		mutex:       &sync.RWMutex{},
	}
}

// NewProcessWithInfo creates a new thread with an initialized task info.
func NewProcessWithInfo(hash uint32, info *TaskInfo) *Process {
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
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.processHash
}

// GetParentHash returns the hash of the parent.
func (p *Process) GetParentHash() uint32 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.parentHash
}

// GetInfo returns a instanced task info.
func (p *Process) GetInfo() *TaskInfo {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.info
}

// GetExecutable returns a instanced executable info.
func (p *Process) GetExecutable() *FileInfo {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.executable
}

// Setters

// SetParentHash sets the hash of the parent.
func (p *Process) SetParentHash(parentHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.parentHash = parentHash
}

//
// Children and Threads
//

// AddChild adds a child to the process.
func (p *Process) AddChild(childHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.addChild(childHash)
}

// AddThread adds a thread to the process.
func (p *Process) AddThread(threadHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.addThread(threadHash)
}

// GetChildren returns the children of the process.
func (p *Process) GetChildren() []uint32 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	children := make([]uint32, len(p.children))
	i := 0
	for child := range p.children {
		children[i] = child
		i++
	}
	return children
}

// GetThreads returns the threads of the process.
func (p *Process) GetThreads() []uint32 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	threads := make([]uint32, len(p.threads))
	i := 0
	for thread := range p.threads {
		threads[i] = thread
		i++
	}
	return threads
}

// DelChild deletes a child from the process.
func (p *Process) DelChild(childHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.delChild(childHash)
}

// DelThread deletes a thread from the process.
func (p *Process) DelThread(threadHash uint32) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.delThread(threadHash)
}

// addChild adds a child to the process.
func (p *Process) addChild(childHash uint32) {
	if _, ok := p.children[childHash]; !ok {
		p.children[childHash] = struct{}{}
	}
}

// addThread adds a thread to the process.
func (p *Process) addThread(threadHash uint32) {
	if _, ok := p.threads[threadHash]; !ok {
		p.threads[threadHash] = struct{}{}
	}
}

// delChild deletes a child from the process.
func (p *Process) delChild(childHash uint32) {
	delete(p.children, childHash)
}

// delThread deletes a thread from the process.
func (p *Process) delThread(threadHash uint32) {
	delete(p.threads, threadHash)
}
