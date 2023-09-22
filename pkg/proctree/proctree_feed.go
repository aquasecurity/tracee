package proctree

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
	if feed.ParentTid == 0 || feed.ParentPid == 0 {
		return errfmt.Errorf("invalid parent task")
	}

	// Update the parent process (might already exist)

	parent, ok := pt.GetProcessByHash(feed.ParentHash) // always a real process
	if !ok {
		parent = pt.GetOrCreateProcessByHash(feed.ParentHash)
		parent.GetInfo().SetFeedAt(
			TaskInfoFeed{
				Tid:         int(feed.ParentTid),
				Pid:         int(feed.ParentPid),
				NsTid:       int(feed.ParentNsTid),
				NsPid:       int(feed.ParentNsPid),
				StartTimeNS: feed.ParentStartTime,
				PPid:        -1, // do not change the parent PID
				NsPPid:      -1, // do not change the ns parent PID
				Uid:         -1, // do not change the parent UID
				Gid:         -1, // do not change the parent GID
			},
			utils.NsSinceBootTimeToTime(feed.TimeStamp),
		)
		// try to enrich from procfs asynchronously (instead of reading procfs continuously)
		pt.FeedFromProcFSAsync(int(feed.ParentPid)) // TODO: only if not in analyze mode
	}

	parent.AddChild(feed.LeaderHash) // add the leader as a child of the parent

	// Update the leader process (might exist, might be the same as child if child is a process)

	leader, ok := pt.GetProcessByHash(feed.LeaderHash)
	if !ok {
		leader = pt.GetOrCreateProcessByHash(feed.LeaderHash)
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
				Uid:         0, // TODO: implement
				Gid:         0, // TODO: implement
			},
			utils.NsSinceBootTimeToTime(feed.TimeStamp),
		)
		// try to enrich from procfs asynchronously (instead of reading procfs continuously)
		pt.FeedFromProcFSAsync(int(feed.LeaderPid)) // TODO: only if not in analyze mode
	}

	leader.SetParentHash(feed.ParentHash)

	// If leader == child, then the child is a process and needs to be updated.

	if feed.ChildHash == feed.LeaderHash {
		leader.GetExecutable().SetFeedAt(
			parent.GetExecutable().GetFeed(),
			utils.NsSinceBootTimeToTime(feed.TimeStamp),
		)
		leader.GetInterpreter().SetFeedAt(
			parent.GetInterpreter().GetFeed(),
			utils.NsSinceBootTimeToTime(feed.TimeStamp),
		)
	}

	// In all cases (task is a process, or a thread) there is a thread entry.

	thread := pt.GetOrCreateThreadByHash(feed.ChildHash)
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
			Uid:         0, // TODO: implement
			Gid:         0, // TODO: implement
		},
		utils.NsSinceBootTimeToTime(feed.TimeStamp),
	)

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

	process := pt.GetOrCreateProcessByHash(feed.TaskHash) // create if not exists

	if feed.ParentHash != 0 {
		process.SetParentHash(feed.ParentHash) // faster than checking if already set
	}

	process.GetInfo().SetNameAt(
		feed.CmdPath,
		utils.NsSinceBootTimeToTime(feed.TimeStamp),
	)

	process.GetExecutable().SetFeedAt(
		FileInfoFeed{
			Path:      feed.PathName,
			Dev:       int(feed.Dev),
			Ctime:     int(feed.Ctime),
			Inode:     int(feed.Inode),
			InodeMode: int(feed.InodeMode),
		},
		utils.NsSinceBootTimeToTime(feed.TimeStamp),
	)

	process.GetInterpreter().SetFeedAt(
		FileInfoFeed{
			Path:      feed.InterpreterPath,
			Dev:       int(feed.InterpreterDev),
			Ctime:     int(feed.InterpreterCtime),
			Inode:     int(feed.InterpreterInode),
			InodeMode: -1, // no inode mode for interpreter
		},
		utils.NsSinceBootTimeToTime(feed.TimeStamp),
	)

	process.GetInterp().SetFeedAt(
		FileInfoFeed{
			Path: feed.Interp,
		},
		utils.NsSinceBootTimeToTime(feed.TimeStamp),
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
	thread, threadOk := pt.GetThreadByHash(feed.TaskHash)
	if threadOk {
		thread.GetInfo().SetExitTime(feed.TimeStamp)
	}
	process, procOk := pt.GetProcessByHash(feed.TaskHash)
	if procOk {
		process.GetInfo().SetExitTime(feed.TimeStamp)
	}

	return nil
}
