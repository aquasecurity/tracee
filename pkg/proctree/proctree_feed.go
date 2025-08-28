package proctree

import (
	"math"
	"path/filepath"
	"time"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/timeutil"
)

//
// Feed process tree using signal events
//

type ForkFeed struct {
	TimeStamp       uint64
	ParentStartTime uint64
	LeaderStartTime uint64
	ChildStartTime  uint64
	ChildHash       uint32
	ParentHash      uint32
	LeaderHash      uint32
	ParentTid       int32
	ParentNsTid     int32
	ParentPid       int32
	ParentNsPid     int32
	LeaderTid       int32
	LeaderNsTid     int32
	LeaderPid       int32
	LeaderNsPid     int32
	ChildTid        int32
	ChildNsTid      int32
	ChildPid        int32
	ChildNsPid      int32
	_               [4]byte // padding
}

func (pt *ProcessTree) setParentFeed(
	parent *Process,
	forkFeed *ForkFeed,
	feedTimeStamp time.Time,
) {
	// NOTE: override all the fields of the taskInfoFeed, to avoid any previous data.
	taskInfoFeed := pt.GetTaskInfoFeedFromPool()

	taskInfoFeed.Name = "" // do not change the parent name
	taskInfoFeed.Tid = forkFeed.ParentTid
	taskInfoFeed.Pid = forkFeed.ParentPid
	taskInfoFeed.NsTid = forkFeed.ParentNsTid
	taskInfoFeed.NsPid = forkFeed.ParentNsPid
	taskInfoFeed.StartTimeNS = forkFeed.ParentStartTime
	taskInfoFeed.PPid = -1            // do not change the parent ppid
	taskInfoFeed.NsPPid = -1          // do not change the parent nsppid
	taskInfoFeed.Uid = math.MaxUint32 // do not change the parent uid
	taskInfoFeed.Gid = math.MaxUint32 // do not change the parent gid
	taskInfoFeed.ExitTimeNS = 0

	parent.GetInfo().SetFeedAt(taskInfoFeed, feedTimeStamp)

	// Release the feed back to the pool as soon as it is not needed anymore
	pt.PutTaskInfoFeedInPool(taskInfoFeed)

	if pt.procfsQuery {
		pt.FeedFromProcFSAsync(forkFeed.ParentPid) // try to enrich ppid and name from procfs
	}
}

func (pt *ProcessTree) setLeaderFeed(
	leader, parent *Process,
	forkFeed *ForkFeed,
	feedTimeStamp time.Time,
) {
	// NOTE: override all the fields of the taskInfoFeed, to avoid any previous data.
	taskInfoFeed := pt.GetTaskInfoFeedFromPool()

	taskInfoFeed.Name = parent.GetInfo().GetName()
	taskInfoFeed.Tid = forkFeed.LeaderTid
	taskInfoFeed.Pid = forkFeed.LeaderPid
	taskInfoFeed.NsTid = forkFeed.LeaderNsTid
	taskInfoFeed.NsPid = forkFeed.LeaderNsPid
	taskInfoFeed.StartTimeNS = forkFeed.LeaderStartTime
	taskInfoFeed.PPid = forkFeed.ParentPid
	taskInfoFeed.NsPPid = forkFeed.ParentNsPid
	taskInfoFeed.Uid = math.MaxUint32 // do not change the leader uid
	taskInfoFeed.Gid = math.MaxUint32 // do not change the leader gid
	taskInfoFeed.ExitTimeNS = 0

	leader.GetInfo().SetFeedAt(taskInfoFeed, feedTimeStamp)

	// Release the feed back to the pool as soon as it is not needed anymore
	pt.PutTaskInfoFeedInPool(taskInfoFeed)

	if pt.procfsQuery {
		pt.FeedFromProcFSAsync(forkFeed.LeaderPid) // try to enrich name from procfs if needed
	}
}

func (pt *ProcessTree) setThreadFeed(
	thread *Thread,
	leader *Process,
	forkFeed *ForkFeed,
	feedTimeStamp time.Time,
) {
	// NOTE: override all the fields of the taskInfoFeed, to avoid any previous data.
	taskInfoFeed := pt.GetTaskInfoFeedFromPool()

	taskInfoFeed.Name = leader.GetInfo().GetName()
	taskInfoFeed.Tid = forkFeed.ChildTid
	taskInfoFeed.Pid = forkFeed.ChildPid
	taskInfoFeed.NsTid = forkFeed.ChildNsTid
	taskInfoFeed.NsPid = forkFeed.ChildNsPid
	taskInfoFeed.StartTimeNS = forkFeed.ChildStartTime
	taskInfoFeed.PPid = forkFeed.ParentPid
	taskInfoFeed.NsPPid = forkFeed.ParentNsPid
	taskInfoFeed.Uid = math.MaxUint32 // do not change the thread uid
	taskInfoFeed.Gid = math.MaxUint32 // do not change the thread gid
	taskInfoFeed.ExitTimeNS = 0

	thread.GetInfo().SetFeedAt(taskInfoFeed, feedTimeStamp)

	// Release the feed back to the pool as soon as it is not needed anymore
	pt.PutTaskInfoFeedInPool(taskInfoFeed)
}

// FeedFromFork feeds the process tree with a fork event.
func (pt *ProcessTree) FeedFromFork(feed *ForkFeed) error {
	if feed.ChildHash == 0 || feed.ParentHash == 0 {
		return errfmt.Errorf("invalid task hash")
	}
	if feed.ChildTid == 0 || feed.ChildPid == 0 {
		return errfmt.Errorf("invalid child task")
	}

	feedTimeStamp := timeutil.NsSinceEpochToTime(feed.TimeStamp)
	// Parent PID or TID might be 0 for init (and docker containers)
	// if feed.ParentTid == 0 || feed.ParentPid == 0 {
	// 	return errfmt.Errorf("invalid parent task")
	// }

	// Update the parent process (might already exist)

	parent, found := pt.GetProcessByHash(feed.ParentHash) // always a real process
	if !found {
		parent = pt.GetOrCreateProcessByHash(feed.ParentHash)
	}

	// No need to create more changelogs for the parent process if it already exists. Some nodes
	// might have been created by execve() events, and those need to be updated (they're missing
	// ppid, for example).

	if !found || parent.GetInfo().GetPid() != feed.ParentPid {
		pt.setParentFeed(parent, feed, feedTimeStamp)
	}

	pt.AddChildToProcess(feed.ParentHash, feed.LeaderHash) // add the leader as a child of the parent

	// Update the leader process (might exist, might be the same as child if child is a process)

	leader, found := pt.GetProcessByHash(feed.LeaderHash)
	if !found {
		leader = pt.GetOrCreateProcessByHash(feed.LeaderHash)
	}

	// Same case here (for events out of order created by execve first)

	if !found || leader.GetInfo().GetPPid() != feed.ParentPid {
		pt.setLeaderFeed(leader, parent, feed, feedTimeStamp)
	}

	leader.SetParentHash(feed.ParentHash) // add the parent as the parent of the leader

	// Check if the leader and child are the same (it means it is a real process, or a "thread group
	// leader" of a single threaded process).

	if feed.ChildHash == feed.LeaderHash {
		fileInfoFeed := parent.GetExecutable().GetFeed()
		leader.GetExecutable().SetFeedAt(
			&fileInfoFeed,
			feedTimeStamp,
		)
	}

	// In all cases (task is a process, or a thread) there is a thread entry.

	thread, found := pt.GetThreadByHash(feed.ChildHash)
	if !found {
		thread = pt.GetOrCreateThreadByHash(feed.ChildHash)
	}

	// Same case here (for events out of order created by execve first)

	if !found || thread.GetInfo().GetPPid() != feed.ParentPid {
		pt.setThreadFeed(thread, leader, feed, feedTimeStamp)
	}

	thread.SetParentHash(feed.ParentHash)                  // all threads have the same parent as the thread group leader
	thread.SetLeaderHash(feed.LeaderHash)                  // thread group leader is a "process" and a "thread"
	pt.AddThreadToProcess(feed.LeaderHash, feed.ChildHash) // add the thread to the thread group leader

	return nil
}

type ExecFeed struct {
	TimeStamp         uint64
	StartTime         uint64
	Inode             uint64
	Ctime             uint64
	CmdPath           string
	PathName          string
	Interp            string
	StdinPath         string
	Pid               int32
	Tid               int32
	PPid              int32
	HostPid           int32
	HostTid           int32
	HostPPid          int32
	TaskHash          uint32
	ParentHash        uint32
	LeaderHash        uint32
	Dev               uint32
	InvokedFromKernel bool
	_                 [3]byte // padding
	InodeMode         uint16
	StdinType         uint16

	// InterpreterPath   string
	// InterpreterDev    uint32
	// InterpreterInode  uint64
	// InterpreterCtime  uint64
}

const COMM_LEN = 16

// FeedFromExec feeds the process tree with an exec event.
func (pt *ProcessTree) FeedFromExec(feed *ExecFeed) error {
	if feed.LeaderHash != 0 && feed.TaskHash != feed.LeaderHash {
		// Running execve() from a thread is discouraged and behavior can be unexpected:
		//
		// 1. All threads are terminated.
		// 2. PID remains the same.
		// 3. New process is single threaded.
		// 4. Inherited Attributed (open fds, proc group, ID, UID, GID, ... are retained)
		// 5. Still, it isn't forbidden and should be handled.

		// TODO: handle execve() from a thread
		logger.Debugw("exec event received for a thread", "taskHash", feed.TaskHash)
		return nil
	}

	// Update the process: it is very likely that the process already exists because of the fork
	// event. There are small chances that it might not exist yet due to signal event ordering. If
	// that is the case, the process will be created and only the information about the
	// executable/interpreter will be updated. This way, when the fork event is received, the
	// process will be updated with the correct information.

	process := pt.GetOrCreateProcessByHash(feed.TaskHash)

	if feed.ParentHash != 0 {
		process.SetParentHash(feed.ParentHash) // faster than checking if already set
	}

	execTimestamp := timeutil.NsSinceEpochToTime(feed.TimeStamp)
	basename := filepath.Base(feed.CmdPath)
	comm := string([]byte(basename[:min(len(basename), COMM_LEN)]))

	// NOTE: override all the fields of the taskInfoFeed, to avoid any previous data.
	taskFeed := pt.GetTaskInfoFeedFromPool()

	taskFeed.StartTimeNS = feed.StartTime
	taskFeed.ExitTimeNS = 0
	taskFeed.Name = comm
	taskFeed.NsTid = feed.Tid
	taskFeed.NsPid = feed.Pid
	taskFeed.NsPPid = feed.PPid
	taskFeed.Tid = feed.HostTid
	taskFeed.Pid = feed.HostPid
	taskFeed.PPid = feed.HostPPid
	taskFeed.Uid = math.MaxUint32
	taskFeed.Gid = math.MaxUint32

	process.GetInfo().SetFeedAt(taskFeed, execTimestamp)

	// Release the feed back to the pool as soon as it is not needed anymore
	pt.PutTaskInfoFeedInPool(taskFeed)

	// NOTE: override all the fields of the fileInfoFeed, to avoid any previous data.
	fileInfoFeed := pt.GetFileInfoFeedFromPool()

	fileInfoFeed.Path = feed.PathName
	fileInfoFeed.Dev = feed.Dev
	fileInfoFeed.Ctime = feed.Ctime
	fileInfoFeed.Inode = feed.Inode
	fileInfoFeed.InodeMode = feed.InodeMode

	process.GetExecutable().SetFeedAt(fileInfoFeed, execTimestamp)

	// Release the feed back to the pool as soon as it is not needed anymore
	pt.PutFileInfoFeedInPool(fileInfoFeed)

	return nil
}

type ExitFeed struct {
	TimeStamp  uint64
	TaskHash   uint32
	ExitCode   int32
	SignalCode int32
	Group      bool
	_          [3]byte // padding
}

// FeedFromExit feeds the process tree with an exit event.
func (pt *ProcessTree) FeedFromExit(feed *ExitFeed) error {
	// Always create a tree node because the events might be received out of order.

	// NOTE: Currently FeedFromExit is only using TaskHash and TimeStamp from the ExitFeed.
	// So the other fields are commented out for now.
	//
	// TODO: Analyze if the other fields will be needed in the future.

	thread := pt.GetOrCreateThreadByHash(feed.TaskHash)
	thread.GetInfo().SetExitTime(feed.TimeStamp)

	process := pt.GetOrCreateProcessByHash(feed.TaskHash)
	process.GetInfo().SetExitTime(feed.TimeStamp)

	return nil
}
