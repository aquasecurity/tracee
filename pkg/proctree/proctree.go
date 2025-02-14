package proctree

import (
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
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

const (
	DefaultProcessCacheSize = 10928
	DefaultThreadCacheSize  = 21856
)

type SourceType int

const (
	SourceNone    SourceType = iota // disabled
	SourceSignals                   // event from control plane enrich the process tree
	SourceEvents                    // event from pipeline enrich the process tree
	SourceBoth                      // events from both pipelines enrich the process tree
)

func (s SourceType) String() string {
	switch s {
	case SourceNone:
		return "none"
	case SourceSignals:
		return "signals"
	case SourceEvents:
		return "events"
	case SourceBoth:
		return "signals and events"
	}
	return "unknown"
}

type ProcTreeConfig struct {
	Source               SourceType
	ProcessCacheSize     int
	ThreadCacheSize      int
	ProcfsInitialization bool // Determine whether to scan procfs data for process tree initialization
	ProcfsQuerying       bool // Determine whether to query procfs for missing information during runtime
}

// ProcessTree is a tree of processes and threads.
type ProcessTree struct {
	processesLRU      *lru.Cache[uint32, *Process]   // hash -> process
	threadsLRU        *lru.Cache[uint32, *Thread]    // hash -> threads
	processesThreads  map[uint32]map[uint32]struct{} // process hash -> thread hashes
	processesChildren map[uint32]map[uint32]struct{} // process hash -> children hashes
	procfsChan        chan int32                     // channel of pids to read from procfs
	procfsOnce        *sync.Once                     // busy loop debug message throttling
	ctx               context.Context                // context for the process tree
	procfsQuery       bool

	// mutexes
	processesThreadsMtx  sync.RWMutex
	processesChildrenMtx sync.RWMutex

	// pools
	forkFeedPool     *sync.Pool // pool of ForkFeed instances
	execFeedPool     *sync.Pool // pool of ExecFeed instances
	exitFeedPool     *sync.Pool // pool of ExitFeed instances
	taskInfoFeedPool *sync.Pool // pool of TaskInfoFeed instances
	fileInfoFeedPool *sync.Pool // pool of FileInfoFeed instances
}

// NewProcessTree creates a new process tree.
func NewProcessTree(ctx context.Context, config ProcTreeConfig) (*ProcessTree, error) {
	procTree := &ProcessTree{
		processesThreads:  make(map[uint32]map[uint32]struct{}),
		processesChildren: make(map[uint32]map[uint32]struct{}),
		procfsOnce:        new(sync.Once),
		ctx:               ctx,
		procfsQuery:       config.ProcfsQuerying,
		forkFeedPool: &sync.Pool{
			New: func() interface{} {
				return &ForkFeed{}
			},
		},
		execFeedPool: &sync.Pool{
			New: func() interface{} {
				return &ExecFeed{}
			},
		},
		exitFeedPool: &sync.Pool{
			New: func() interface{} {
				return &ExitFeed{}
			},
		},
		taskInfoFeedPool: &sync.Pool{
			New: func() interface{} {
				return &TaskInfoFeed{}
			},
		},
		fileInfoFeedPool: &sync.Pool{
			New: func() interface{} {
				return &FileInfoFeed{}
			},
		},
	}

	var err error
	procEvicted := 0
	thrEvicted := 0

	// Create caches for processes.
	procTree.processesLRU, err = lru.NewWithEvict[uint32, *Process](
		config.ProcessCacheSize,
		func(key uint32, value *Process) {
			procTree.EvictThreads(key)
			procTree.EvictChildren(key)
			procEvicted++
		},
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// Create caches for threads.
	procTree.threadsLRU, err = lru.NewWithEvict[uint32, *Thread](
		config.ThreadCacheSize,
		func(key uint32, value *Thread) {
			thrEvicted++
		},
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// Report cache stats if debug is enabled.
	go func() {
		ticker15s := time.NewTicker(15 * time.Second)
		ticker1m := time.NewTicker(1 * time.Minute)
		defer ticker15s.Stop()
		defer ticker1m.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker15s.C:
				if procEvicted != 0 || thrEvicted != 0 {
					logger.Debugw("proctree cache stats",
						"processes evicted", procEvicted,
						"total processes", procTree.processesLRU.Len(),
						"threads evicted", thrEvicted,
						"total threads", procTree.threadsLRU.Len(),
					)
					procEvicted = 0
					thrEvicted = 0
				}

				// For debugging purposes, print the entire process tree.
				// fmt.Println(procTree.String())
			case <-ticker1m.C:
				logger.Debugw("proctree cache stats",
					"total processes", procTree.processesLRU.Len(),
					"total threads", procTree.threadsLRU.Len(),
				)
			}
		}
	}()

	if config.ProcfsInitialization {
		// Walk procfs and feed the process tree with data.
		procTree.FeedFromProcFSAsync(AllPIDs)
	}

	return procTree, nil
}

//
// Processes
//

// GetProcessByHash returns a process by its hash.
func (pt *ProcessTree) GetProcessByHash(hash uint32) (*Process, bool) {
	process, ok := pt.processesLRU.Get(hash)
	return process, ok
}

// GetOrCreateProcessByHash returns a process by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateProcessByHash(hash uint32) *Process {
	process, ok := pt.processesLRU.Get(hash)
	if !ok {
		var taskInfo *TaskInfo

		// Each process must have a thread with thread ID matching its process ID.
		// Both share the same info as both represent the same task in the kernel.
		thread, ok := pt.threadsLRU.Get(hash)
		if ok {
			taskInfo = thread.GetInfo()
		} else {
			taskInfo = NewTaskInfo()
			thread = NewThread(hash, taskInfo) // create a new thread
			pt.threadsLRU.Add(hash, thread)
		}

		thread.SetLeaderHash(hash)

		process = NewProcess(hash, taskInfo) // create a new process
		pt.AddThreadToProcess(hash, hash)    // add itself as a thread
		pt.processesLRU.Add(hash, process)

		return process
	}

	return process // return an existing process
}

// Process Threads and Children

// GetThreads returns a list of thread hashes for a given process hash.
func (pt *ProcessTree) GetThreads(processHash uint32) []uint32 {
	pt.processesThreadsMtx.RLock()
	defer pt.processesThreadsMtx.RUnlock()

	threadsMap, ok := pt.processesThreads[processHash]
	if !ok {
		return nil
	}

	threads := make([]uint32, 0, len(threadsMap))
	for thread := range threadsMap {
		threads = append(threads, thread)
	}

	return threads
}

// GetChildren returns a list of children hashes for a given process hash.
func (pt *ProcessTree) GetChildren(processHash uint32) []uint32 {
	pt.processesChildrenMtx.RLock()
	defer pt.processesChildrenMtx.RUnlock()

	childrenMap, ok := pt.processesChildren[processHash]
	if !ok {
		return nil
	}

	children := make([]uint32, 0, len(childrenMap))
	for child := range childrenMap {
		children = append(children, child)
	}

	return children
}

// AddThreadToProcess adds a thread to a process.
func (pt *ProcessTree) AddThreadToProcess(processHash uint32, threadHash uint32) {
	if processHash == 0 || threadHash == 0 {
		return
	}

	pt.processesThreadsMtx.Lock()
	defer pt.processesThreadsMtx.Unlock()

	if _, ok := pt.processesThreads[processHash]; !ok {
		pt.processesThreads[processHash] = make(map[uint32]struct{})
	}

	pt.processesThreads[processHash][threadHash] = struct{}{}
}

// AddChildToProcess adds a child to a process.
func (pt *ProcessTree) AddChildToProcess(processHash uint32, childHash uint32) {
	if processHash == 0 || childHash == 0 {
		return
	}

	pt.processesChildrenMtx.Lock()
	defer pt.processesChildrenMtx.Unlock()

	if _, ok := pt.processesChildren[processHash]; !ok {
		pt.processesChildren[processHash] = make(map[uint32]struct{})
	}

	pt.processesChildren[processHash][childHash] = struct{}{}
}

// EvictThreads evicts threads from a process.
func (pt *ProcessTree) EvictThreads(processHash uint32) {
	pt.processesThreadsMtx.Lock()
	defer pt.processesThreadsMtx.Unlock()

	delete(pt.processesThreads, processHash)
}

// EvictChildren evicts children from a process.
func (pt *ProcessTree) EvictChildren(processHash uint32) {
	pt.processesChildrenMtx.Lock()
	defer pt.processesChildrenMtx.Unlock()

	delete(pt.processesChildren, processHash)
}

//
// Threads
//

// GetThreadByHash returns a thread by its hash.
func (pt *ProcessTree) GetThreadByHash(hash uint32) (*Thread, bool) {
	thread, ok := pt.threadsLRU.Get(hash)
	return thread, ok
}

// GetOrCreateThreadByHash returns a thread by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateThreadByHash(hash uint32) *Thread {
	thread, ok := pt.threadsLRU.Get(hash)
	if !ok {
		var taskInfo *TaskInfo

		// Create a new thread
		// If the thread is a leader task, sync its info with the process instance info.
		process, ok := pt.processesLRU.Get(hash)
		if ok {
			taskInfo = process.GetInfo()
		} else {
			taskInfo = NewTaskInfo()
		}

		thread = NewThread(hash, taskInfo) // create a new thread
		pt.threadsLRU.Add(hash, thread)

		return thread
	}

	return thread // return an existing thread
}

//
// Pools
//

// GetForkFeedFromPool returns a ForkFeed from the pool, or creates a new one if the pool is empty.
// ForkFeed certainly contains old data, so it must be updated before use.
func (pt *ProcessTree) GetForkFeedFromPool() *ForkFeed {
	// revive:disable:unchecked-type-assertion
	return pt.forkFeedPool.Get().(*ForkFeed)
	// revive:enable:unchecked-type-assertion
}

// PutForkFeedInPool returns a ForkFeed to the pool.
func (pt *ProcessTree) PutForkFeedInPool(forkFeed *ForkFeed) {
	pt.forkFeedPool.Put(forkFeed)
}

// GetExecFeedFromPool returns a ExecFeed from the pool, or creates a new one if the pool is empty.
// ExecFeed certainly contains old data, so it must be updated before use.
func (pt *ProcessTree) GetExecFeedFromPool() *ExecFeed {
	// revive:disable:unchecked-type-assertion
	return pt.execFeedPool.Get().(*ExecFeed)
	// revive:enable:unchecked-type-assertion
}

// PutExecFeedInPool returns a ExecFeed to the pool.
func (pt *ProcessTree) PutExecFeedInPool(execFeed *ExecFeed) {
	pt.execFeedPool.Put(execFeed)
}

// GetExitFeedFromPool returns a ExitFeed from the pool, or creates a new one if the pool is empty.
// ExitFeed certainly contains old data, so it must be updated before use.
func (pt *ProcessTree) GetExitFeedFromPool() *ExitFeed {
	// revive:disable:unchecked-type-assertion
	return pt.exitFeedPool.Get().(*ExitFeed)
	// revive:enable:unchecked-type-assertion
}

// PutExitFeedInPool returns a ExitFeed to the pool.
func (pt *ProcessTree) PutExitFeedInPool(exitFeed *ExitFeed) {
	pt.exitFeedPool.Put(exitFeed)
}

// GetTaskInfoFeedFromPool returns a TaskInfoFeed from the pool, or creates a new one if the pool is empty.
// TaskInfoFeed certainly contains old data, so it must be updated before use.
func (pt *ProcessTree) GetTaskInfoFeedFromPool() *TaskInfoFeed {
	// revive:disable:unchecked-type-assertion
	return pt.taskInfoFeedPool.Get().(*TaskInfoFeed)
	// revive:enable:unchecked-type-assertion
}

// PutTaskInfoFeedInPool returns a TaskInfoFeed to the pool.
func (pt *ProcessTree) PutTaskInfoFeedInPool(taskInfoFeed *TaskInfoFeed) {
	pt.taskInfoFeedPool.Put(taskInfoFeed)
}

// GetFileInfoFeedFromPool returns a FileInfoFeed from the pool, or creates a new one if the pool is empty.
// FileInfoFeed certainly contains old data, so it must be updated before use.
func (pt *ProcessTree) GetFileInfoFeedFromPool() *FileInfoFeed {
	// revive:disable:unchecked-type-assertion
	return pt.fileInfoFeedPool.Get().(*FileInfoFeed)
	// revive:enable:unchecked-type-assertion
}

// PutFileInfoFeedInPool returns a FileInfoFeed to the pool.
func (pt *ProcessTree) PutFileInfoFeedInPool(fileInfoFeed *FileInfoFeed) {
	pt.fileInfoFeedPool.Put(fileInfoFeed)
}
