package proctree

import (
	"sync/atomic"
)

//
// Process
//

// Process represents a process.
type Process struct {
	processHash uint32        // hash of process (immutable, so no need of concurrency control)
	parentHash  atomic.Uint32 // hash of parent
	info        *TaskInfo     // task info (immutable pointer)
	executable  *FileInfo     // executable info (immutable pointer)
}

// NewProcess creates a new thread with an initialized task info.
func NewProcess(hash uint32, info *TaskInfo) *Process {
	return &Process{
		processHash: hash,
		parentHash:  atomic.Uint32{},
		info:        info,
		executable:  NewFileInfo(),
	}
}

// Getters

// GetHash returns the hash of the process.
func (p *Process) GetHash() uint32 {
	return p.processHash // immutable
}

// GetParentHash returns the hash of the parent.
func (p *Process) GetParentHash() uint32 {
	return p.parentHash.Load()
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
	p.parentHash.Store(parentHash)
}
