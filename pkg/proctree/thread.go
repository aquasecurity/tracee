package proctree

import "sync/atomic"

// Thread represents a thread.
type Thread struct {
	threadHash uint32        // hash of thread (immutable, so no need of concurrency control)
	parentHash atomic.Uint32 // hash of parent
	leaderHash atomic.Uint32 // hash of thread group leader
	_          [4]byte       // padding
	info       *TaskInfo     // task info (immutable pointer)
}

// NOTE: The importance of having the thread group leader hash to each thread is the following: the
// thread group leader is considered a "Process", in the proctree, and it will have all the
// information regarding the process, such as the executable and interpreter. Whenever an artifact
// log, for a thread, is needed, the thread group leader hash will be used to find the process so it
// can be logged as a process artifact.

// NewThread creates a new thread with an initialized task info.
func NewThread(hash uint32, info *TaskInfo) *Thread {
	return &Thread{
		threadHash: hash,
		parentHash: atomic.Uint32{},
		leaderHash: atomic.Uint32{},
		info:       info,
	}
}

// Getters

// GetHash returns the hash of the thread.
func (t *Thread) GetHash() uint32 {
	return t.threadHash // immutable
}

// GetParentHash returns the hash of the parent.
func (t *Thread) GetParentHash() uint32 {
	return t.parentHash.Load()
}

// GEtLeaderHash returns the hash of the thread group leader.
func (t *Thread) GetLeaderHash() uint32 {
	return t.leaderHash.Load()
}

// GetInfo returns a instanced task info.
func (t *Thread) GetInfo() *TaskInfo {
	return t.info // immutable pointer
}

// Setters

// SetParentHash sets the hash of the parent.
func (t *Thread) SetParentHash(parentHash uint32) {
	t.parentHash.Store(parentHash)
}

// SetLeaderHash sets the hash of the thread group leader.
func (t *Thread) SetLeaderHash(leaderHash uint32) {
	t.leaderHash.Store(leaderHash)
}
