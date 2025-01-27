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
	processes   *lru.Cache[uint32, *Process] // hash -> process
	threads     *lru.Cache[uint32, *Thread]  // hash -> threads
	procfsChan  chan int                     // channel of pids to read from procfs
	procfsOnce  *sync.Once                   // busy loop debug message throttling
	ctx         context.Context              // context for the process tree
	procfsQuery bool

	// pools
	forkFeedPool     *sync.Pool // pool of ForkFeed instances
	execFeedPool     *sync.Pool // pool of ExecFeed instances
	exitFeedPool     *sync.Pool // pool of ExitFeed instances
	taskInfoFeedPool *sync.Pool // pool of TaskInfoFeed instances
	fileInfoFeedPool *sync.Pool // pool of FileInfoFeed instances
}

// NewProcessTree creates a new process tree.
func NewProcessTree(ctx context.Context, config ProcTreeConfig) (*ProcessTree, error) {
	procEvited := 0
	thrEvicted := 0

	// Create caches for processes.
	processes, err := lru.NewWithEvict[uint32, *Process](
		config.ProcessCacheSize,
		func(uint32, *Process) {
			procEvited++
		},
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// Create caches for threads.
	threads, err := lru.NewWithEvict[uint32, *Thread](
		config.ThreadCacheSize,
		func(uint32, *Thread) {
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
				if procEvited != 0 || thrEvicted != 0 {
					logger.Debugw("proctree cache stats",
						"processes evicted", procEvited,
						"total processes", processes.Len(),
						"threads evicted", thrEvicted,
						"total threads", threads.Len(),
					)
					procEvited = 0
					thrEvicted = 0
				}
			case <-ticker1m.C:
				logger.Debugw("proctree cache stats",
					"total processes", processes.Len(),
					"total threads", threads.Len(),
				)
			}
		}
	}()

	procTree := &ProcessTree{
		processes:   processes,
		threads:     threads,
		procfsOnce:  new(sync.Once),
		ctx:         ctx,
		procfsQuery: config.ProcfsQuerying,
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
	process, ok := pt.processes.Get(hash)
	return process, ok
}

// GetOrCreateProcessByHash returns a process by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateProcessByHash(hash uint32) *Process {
	process, ok := pt.processes.Get(hash)
	if !ok {
		var taskInfo *TaskInfo

		// Each process must have a thread with thread ID matching its process ID.
		// Both share the same info as both represent the same task in the kernel.
		thread, ok := pt.threads.Get(hash)
		if ok {
			taskInfo = thread.GetInfo()
		} else {
			taskInfo = NewTaskInfo()
			thread = NewThread(hash, taskInfo) // create a new thread
			pt.threads.Add(hash, thread)
		}

		thread.SetLeaderHash(hash)

		process = NewProcess(hash, taskInfo) // create a new process
		process.AddThread(hash)
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
	thread, ok := pt.threads.Get(hash)
	return thread, ok
}

// GetOrCreateThreadByHash returns a thread by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateThreadByHash(hash uint32) *Thread {
	thread, ok := pt.threads.Get(hash)
	if !ok {
		var taskInfo *TaskInfo

		// Create a new thread
		// If the thread is a leader task, sync its info with the process instance info.
		process, ok := pt.processes.Get(hash)
		if ok {
			taskInfo = process.GetInfo()
		} else {
			taskInfo = NewTaskInfo()
		}

		thread = NewThread(hash, taskInfo) // create a new thread
		pt.threads.Add(hash, thread)

		return thread
	}

	return thread // return an existing thread
}

// Pools

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
