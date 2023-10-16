package proctree

import (
	"sync"
)

// Thread represents a thread.
type Thread struct {
	threadHash uint32    // hash of thread
	parentHash uint32    // hash of parent
	leaderHash uint32    // hash of thread group leader
	info       *TaskInfo // task info
	// Control fields
	mutex *sync.RWMutex // mutex to protect the thread
}

// NOTE: The importance of having the thread group leader hash to each thread is the following: the
// thread group leader is considered a "Process", in the proctree, and it will have all the
// information regarding the process, such as the executable and interpreter. Whenever an artifact
// log, for a thread, is needed, the thread group leader hash will be used to find the process so it
// can be logged as a process artifact.

// NewThread creates a new thread.
func NewThread(hash uint32) *Thread {
	return &Thread{
		threadHash: hash,
		parentHash: 0,
		info:       NewTaskInfo(),
		mutex:      &sync.RWMutex{},
	}
}

// Getters

// GetHash returns the hash of the thread.
func (t *Thread) GetHash() uint32 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.threadHash
}

// GetParentHash returns the hash of the parent.
func (t *Thread) GetParentHash() uint32 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.parentHash
}

// GEtLeaderHash returns the hash of the thread group leader.
func (t *Thread) GetLeaderHash() uint32 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.leaderHash
}

// GetInfo returns a instanced task info.
func (t *Thread) GetInfo() *TaskInfo {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.info
}

// Setters

// SetParentHash sets the hash of the parent.
func (t *Thread) SetParentHash(parentHash uint32) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.parentHash = parentHash
}

// SetLeaderHash sets the hash of the thread group leader.
func (t *Thread) SetLeaderHash(leaderHash uint32) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.leaderHash = leaderHash
}
