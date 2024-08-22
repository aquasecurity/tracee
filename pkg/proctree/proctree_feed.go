package proctree

import (
	"path/filepath"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
)

//
// Feed process tree using signal events
//

type ForkFeed struct {
	TimeStamp       uint64
	ChildHash       uint32
	ParentHash      uint32
	LeaderHash      uint32
	ParentTid       int32
	ParentNsTid     int32
	ParentPid       int32
	ParentNsPid     int32
	ParentStartTime uint64
	LeaderTid       int32
	LeaderNsTid     int32
	LeaderPid       int32
	LeaderNsPid     int32
	LeaderStartTime uint64
	ChildTid        int32
	ChildNsTid      int32
	ChildPid        int32
	ChildNsPid      int32
	ChildStartTime  uint64
}

// FeedFromFork feeds the process tree with a fork event.
func (pt *ProcessTree) FeedFromFork(feed ForkFeed) error {
	if feed.ChildHash == 0 || feed.ParentHash == 0 {
		return errfmt.Errorf("invalid task hash")
	}
	if feed.ChildTid == 0 || feed.ChildPid == 0 {
		return errfmt.Errorf("invalid child task")
	}

	feedTimeStamp := traceetime.NsSinceEpochToTime(feed.TimeStamp)
	// Parent PID or TID might be 0 for init (and docker containers)
	// if feed.ParentTid == 0 || feed.ParentPid == 0 {
	// 	return errfmt.Errorf("invalid parent task")
	// }

	// Update the parent process (might already exist)

	setParentFeed := func(parent *Process) {
		parent.GetInfo().SetFeedAt(
			TaskInfoFeed{
				Name:        "", // do not change the parent name
				Tid:         int(feed.ParentTid),
				Pid:         int(feed.ParentPid),
				NsTid:       int(feed.ParentNsTid),
				NsPid:       int(feed.ParentNsPid),
				StartTimeNS: feed.ParentStartTime,
				PPid:        -1, // do not change the parent ppid
				NsPPid:      -1, // do not change the parent nsppid
				Uid:         -1, // do not change the parent uid
				Gid:         -1, // do not change the parent gid
			},
			feedTimeStamp,
		)
		if pt.procfsQuery {
			pt.FeedFromProcFSAsync(int(feed.ParentPid)) // try to enrich ppid and name from procfs
		}
	}

	parent, found := pt.GetProcessByHash(feed.ParentHash) // always a real process
	if !found {
		parent = pt.GetOrCreateProcessByHash(feed.ParentHash)
	}

	// No need to create more changelogs for the parent process if it already exists. Some nodes
	// might have been created by execve() events, and those need to be updated (they're missing
	// ppid, for example).

	if !found || parent.GetInfo().GetPid() != int(feed.ParentPid) {
		setParentFeed(parent)
	}

	parent.AddChild(feed.LeaderHash) // add the leader as a child of the parent

	// Update the leader process (might exist, might be the same as child if child is a process)

	setLeaderFeed := func(leader *Process) {
		leader.GetInfo().SetFeedAt(
			TaskInfoFeed{
				Name:        parent.GetInfo().GetName(),
				Tid:         int(feed.LeaderTid),
				Pid:         int(feed.LeaderPid),
				NsTid:       int(feed.LeaderNsTid),
				NsPid:       int(feed.LeaderNsPid),
				StartTimeNS: feed.LeaderStartTime,
				PPid:        int(feed.ParentPid),
				NsPPid:      int(feed.ParentNsPid),
				Uid:         -1, // do not change the parent ui
				Gid:         -1, // do not change the parent gid
			},
			feedTimeStamp,
		)
		if pt.procfsQuery {
			pt.FeedFromProcFSAsync(int(feed.LeaderPid)) // try to enrich name from procfs if needed
		}
	}

	leader, found := pt.GetProcessByHash(feed.LeaderHash)
	if !found {
		leader = pt.GetOrCreateProcessByHash(feed.LeaderHash)
	}

	// Same case here (for events out of order created by execve first)

	if !found || leader.GetInfo().GetPPid() != int(feed.ParentPid) {
		setLeaderFeed(leader)
	}

	leader.SetParentHash(feed.ParentHash) // add the parent as the parent of the leader

	// Check if the leader and child are the same (it means it is a real process, or a "thread group
	// leader" of a single threaded process).

	if feed.ChildHash == feed.LeaderHash {
		leader.GetExecutable().SetFeedAt(
			parent.GetExecutable().GetFeed(),
			feedTimeStamp,
		)
		leader.GetInterpreter().SetFeedAt(
			parent.GetInterpreter().GetFeed(),
			feedTimeStamp,
		)
	}

	// In all cases (task is a process, or a thread) there is a thread entry.

	setThreadFeed := func(thread *Thread) {
		thread.GetInfo().SetFeedAt(
			TaskInfoFeed{
				Name:        leader.GetInfo().GetName(),
				Tid:         int(feed.ChildTid),
				Pid:         int(feed.ChildPid),
				NsTid:       int(feed.ChildNsTid),
				NsPid:       int(feed.ChildNsPid),
				StartTimeNS: feed.ChildStartTime,
				PPid:        int(feed.ParentPid),
				NsPPid:      int(feed.ParentNsPid),
				Uid:         -1, // do not change the thread uid
				Gid:         -1, // do not change the thread gid
			},
			feedTimeStamp,
		)
	}

	thread, found := pt.GetThreadByHash(feed.ChildHash)
	if !found {
		thread = pt.GetOrCreateThreadByHash(feed.ChildHash)
	}

	// Same case here (for events out of order created by execve first)

	if !found || thread.GetInfo().GetPPid() != int(feed.ParentPid) {
		setThreadFeed(thread)
	}

	thread.SetParentHash(feed.ParentHash) // all threads have the same parent as the thread group leader
	thread.SetLeaderHash(feed.LeaderHash) // thread group leader is a "process" and a "thread"
	leader.AddThread(feed.ChildHash)      // add the thread to the thread group leader

	return nil
}

type ExecFeed struct {
	TimeStamp         uint64
	TaskHash          uint32
	ParentHash        uint32
	LeaderHash        uint32
	CmdPath           string
	PathName          string
	Dev               uint32
	Inode             uint64
	Ctime             uint64
	InodeMode         uint16
	InterpreterPath   string
	InterpreterDev    uint32
	InterpreterInode  uint64
	InterpreterCtime  uint64
	Interp            string
	StdinType         uint16
	StdinPath         string
	InvokedFromKernel int32
}

const COMM_LEN = 16

// FeedFromExec feeds the process tree with an exec event.
func (pt *ProcessTree) FeedFromExec(feed ExecFeed) error {
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

	execTimestamp := traceetime.NsSinceEpochToTime(feed.TimeStamp)
	basename := filepath.Base(feed.CmdPath)
	comm := string([]byte(basename[:min(len(basename), COMM_LEN)]))
	process.GetInfo().SetNameAt(
		comm,
		execTimestamp,
	)

	process.GetExecutable().SetFeedAt(
		FileInfoFeed{
			Path:      feed.PathName,
			Dev:       int(feed.Dev),
			Ctime:     int(feed.Ctime),
			Inode:     int(feed.Inode),
			InodeMode: int(feed.InodeMode),
		},
		execTimestamp,
	)

	return nil
}

type ExitFeed struct {
	TimeStamp  uint64
	TaskHash   uint32
	ParentHash uint32
	LeaderHash uint32
	ExitCode   int64
	Group      bool
}

// FeedFromExit feeds the process tree with an exit event.
func (pt *ProcessTree) FeedFromExit(feed ExitFeed) error {
	// Always create a tree node because the events might be received out of order.

	thread := pt.GetOrCreateThreadByHash(feed.TaskHash)
	thread.GetInfo().SetExitTime(feed.TimeStamp)

	process := pt.GetOrCreateProcessByHash(feed.TaskHash)
	process.GetInfo().SetExitTime(feed.TimeStamp)

	return nil
}
