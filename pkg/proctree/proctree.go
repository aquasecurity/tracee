package proctree

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// The way the process tree is organized:
//
// 1. All processes and thread group leaders are stored as "processes" (hash -> process).
// 2. All threads are stored as "threads" (hash -> thread).
// 3. Each process has a list of children (hashes of real forked processes).
// 4. Each process, that is a thread group leader, has a list of threads (hashes of threads).
// 5. Each thread has a parent (hash of parent) and a leader (hash of thread group leader).
// 6. Threads from the same thread group have the same parent, the parent of the group leader.
//
// Instruction:
//
// 1. To add an artifact to a process, simply add it to the process entry using its hash.
// 2. To add an artifact to a process parent, use the process parent hash.
// 3. To add an artifact to a thread, pick the group leader hash, add it to its process entry.
//
// NOTE: The importance of having the thread group leader hash to each thread is the following: the
// thread group leader is considered a "Process", in the proctree, and it will have all the
// information regarding the process, such as the executable and interpreter. Whenever an artifact
// log, for a thread, is needed, the thread group leader hash will be used to find the process so it
// can be logged as a process artifact.
//

const proctreeCacheSize = 65536 // 64K (should be enough for most use cases)

// ProcessTree is a tree of processes and threads.
type ProcessTree struct {
	processes *lru.Cache[uint32, *Process] // hash -> process
	threads   *lru.Cache[uint32, *Thread]  // hash -> threads
	mutex     *sync.RWMutex
}

// NewProcessTree creates a new process tree.
func NewProcessTree() (*ProcessTree, error) {
	processes, err := lru.New[uint32, *Process](proctreeCacheSize)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	threads, err := lru.New[uint32, *Thread](proctreeCacheSize)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return &ProcessTree{
		processes: processes,
		threads:   threads,
		mutex:     &sync.RWMutex{},
	}, nil
}

//
// Processes
//

// GetProcessByHash returns a process by its hash.
func (pt *ProcessTree) GetProcessByHash(hash uint32) (*Process, bool) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	process, ok := pt.processes.Get(hash)
	return process, ok
}

// GetOrCreateProcessByHash returns a process by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateProcessByHash(hash uint32) *Process {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	process, ok := pt.processes.Get(hash)
	if !ok {
		process = NewProcess(hash) // create a new process
		pt.processes.Add(hash, process)
		return process
	}

	return process // return an existing process
}

//
// Threads
//

// GetThreadByHash returns a thread by its hash.
func (pt *ProcessTree) GetThreadByHash(hash uint32) (*Thread, bool) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	thread, ok := pt.threads.Get(hash)
	return thread, ok
}

// GetOrCreateThreadByHash returns a thread by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateThreadByHash(hash uint32) *Thread {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	thread, ok := pt.threads.Get(hash)
	if !ok {
		thread = NewThread(hash) // create a new thread
		pt.threads.Add(hash, thread)
		return thread
	}

	return thread // return an existing thread
}
