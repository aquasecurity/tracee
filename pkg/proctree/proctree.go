package proctree

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/aquasecurity/tracee/pkg/logger"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
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
	DefaultProcessCacheSize = 32768
	DefaultThreadCacheSize  = 32768
	DefaultProcessCacheTTL  = time.Second * 120
	DefaultThreadCacheTTL   = time.Second * 120
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
	ProcessCacheTTL      time.Duration
	ThreadCacheTTL       time.Duration
	ProcfsInitialization bool // Determine whether to scan procfs data for process tree initialization
	ProcfsQuerying       bool // Determine whether to query procfs for missing information during runtime
}

// ProcessTree is a tree of processes and threads.
type ProcessTree struct {
	processes      *expirable.LRU[uint32, *Process] // hash -> process
	threads        *expirable.LRU[uint32, *Thread]  // hash -> threads
	procfsChan     chan int                         // channel of pids to read from procfs
	procfsOnce     *sync.Once                       // busy loop debug message throttling
	ctx            context.Context                  // context for the process tree
	procfsQuery    bool
	timeNormalizer traceetime.TimeNormalizer
}

// NewProcessTree creates a new process tree.
func NewProcessTree(ctx context.Context, config ProcTreeConfig, timeNormalizer traceetime.TimeNormalizer) (*ProcessTree, error) {
	procEvited := 0
	thrEvicted := 0

	// Create caches for processes.
	processes := expirable.NewLRU[uint32, *Process](
		config.ProcessCacheSize,
		func(k uint32, v *Process) {
			procEvited++
		},
		config.ProcessCacheTTL,
	)

	// Create caches for threads.
	threads := expirable.NewLRU[uint32, *Thread](
		config.ThreadCacheSize,
		func(k uint32, v *Thread) {
			thrEvicted++
		},
		config.ThreadCacheTTL,
	)

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
		processes:      processes,
		threads:        threads,
		ctx:            ctx,
		procfsQuery:    config.ProcfsQuerying,
		timeNormalizer: timeNormalizer,
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
	if !ok {
		return nil, false
	}

	return process, ok
}

// GetOrCreateProcessByHash returns a process by its hash, or creates a new one if it doesn't exist.
func (pt *ProcessTree) GetOrCreateProcessByHash(hash uint32) *Process {
	process, ok := pt.processes.Get(hash)
	if !ok {
		// Each process must have a thread with thread ID matching its process ID.
		// Both share the same info as both represent the same task in the kernel.
		thread, ok := pt.threads.Get(hash)
		if !ok {
			process = NewProcess(hash) // create a new process
			thread = NewThreadWithInfo(hash, process.GetInfo())
			pt.threads.Add(hash, thread)
		} else {
			process = NewProcessWithInfo(hash, thread.GetInfo())
		}
		pt.processes.Add(hash, process)
		process.AddThread(hash)
		thread.SetLeaderHash(hash)

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
		// Create a new thread
		// If the thread is a leader task, sync its info with the process instance info.
		process, ok := pt.processes.Get(hash)
		if ok {
			thread = NewThreadWithInfo(hash, process.GetInfo())
		} else {
			thread = NewThread(hash)
		}
		pt.threads.Add(hash, thread)
		return thread
	}

	return thread // return an existing thread
}
