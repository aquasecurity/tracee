package proctree

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

const debugMsgs = false // debug messages can be too verbose, so they are disabled by default

const (
	AllPIDs = 0
)

func (pt *ProcessTree) feedFromProcFSLoop() {
	go func() {
		for {
			select {
			case <-time.After(15 * time.Second):
				pt.procfsOnce = new(sync.Once) // reset the once every 15 seconds
			case <-pt.ctx.Done():
				return
			case givenPid := <-pt.procfsChan:
				err := pt.FeedFromProcFS(givenPid)
				if err != nil && debugMsgs {
					logger.Debugw("proctree from procfs (loop)", "err", err)
				}
			}
		}
	}()
}

// FeedFromProcFSAsync feeds the process tree with data from procfs asynchronously.
func (pt *ProcessTree) FeedFromProcFSAsync(givenPid int) {
	if pt.procfsChan == nil {
		logger.Debugw("starting procfs proctree loop") // will tell if called more than once
		pt.procfsChan = make(chan int, 100)
		pt.feedFromProcFSLoop()
	}
	if pt.procfsOnce == nil {
		pt.procfsOnce = new(sync.Once)
	}

	// feed the loop without blocking (if the loop is busy, given pid won't be processed)
	select {
	case pt.procfsChan <- givenPid: // feed the loop
	default:
		pt.procfsOnce.Do(func() {
			// only log once if the loop is busy (avoid spamming the logs), once is reset every 15s
			logger.Debugw("procfs proctree loop is busy")
		})
	}
}

// FeedFromProcFS feeds the process tree with data from procfs.
func (pt *ProcessTree) FeedFromProcFS(givenPid int) error {
	procDir := "/proc"

	// If a PID is given, only deal with that process
	if givenPid > 0 {
		return dealWithProcFsEntry(pt, givenPid)
	}

	// OR... Walk the procfs tree...

	dirs, err := os.ReadDir(procDir)
	if err != nil {
		return errfmt.Errorf("could not read proc dir: %v", err)
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		_ = dealWithProcFsEntry(pt, pid) // run for each existing process
	}

	return nil
}

//
// Helper functions for FeedFromProcFS & FeedFromProcFSAsync
//

// getProcessByPID returns a process by its PID.
func getProcessByPID(pt *ProcessTree, givenPid int) (*Process, error) {
	if givenPid <= 0 {
		return nil, errfmt.Errorf("invalid PID")
	}
	status, err := proc.NewProcStatus(givenPid)
	if err != nil {
		return nil, errfmt.Errorf("%v", err)
	}
	stat, err := proc.NewProcStat(givenPid)
	if err != nil {
		return nil, errfmt.Errorf("%v", err)
	}

	startTimeNs := utils.ClockTicksToNsSinceBootTime(stat.StartTime)
	hash := utils.HashTaskID(uint32(status.GetPid()), startTimeNs) // status pid == tid

	return pt.GetOrCreateProcessByHash(hash), nil
}

// dealWithProc deals with a process from procfs.
func dealWithProc(pt *ProcessTree, givenPid int) error {
	if givenPid <= 0 {
		return errfmt.Errorf("invalid PID")
	}
	status, err := proc.NewProcStatus(givenPid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}
	stat, err := proc.NewProcStat(givenPid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}
	if status.GetPid() != status.GetTgid() {
		return errfmt.Errorf("invalid process") // sanity check (process, not thread)
	}
	if stat.StartTime == 0 {
		return errfmt.Errorf("invalid start time")
	}

	// given process (pid) hash
	startTimeNs := utils.ClockTicksToNsSinceBootTime(stat.StartTime)
	hash := utils.HashTaskID(uint32(status.GetPid()), startTimeNs)

	// update tree for the given process
	process := pt.GetOrCreateProcessByHash(hash)
	procInfo := process.GetInfo()
	procInfo.SetFeed(
		TaskInfoFeed{
			Name:        status.GetName(),
			Tid:         int(status.GetPid()),    // status: pid == tid
			Pid:         int(status.GetTgid()),   // status: tgid == pid
			PPid:        int(status.GetPPid()),   // status: ppid == ppid
			NsTid:       int(status.GetNsPid()),  // status: nspid == nspid
			NsPid:       int(status.GetNsTgid()), // status: nstgid == nspid
			NsPPid:      int(status.GetNsPPid()), // status: nsppid == nsppid
			Uid:         -1,                      // do not change the parent UID
			Gid:         -1,                      // do not change the parent GID
			StartTimeNS: startTimeNs,
		},
	)

	// update given process parent (if exists)
	parent, err := getProcessByPID(pt, status.GetPPid())
	if err == nil {
		parent.AddChild(hash)
		process.SetParentHash(parent.GetHash())
	}

	return nil
}

// dealWithThread deals with a thread from procfs.
func dealWithThread(pt *ProcessTree, pid int, tid int) error {
	if pid <= 0 {
		return errfmt.Errorf("invalid PID")
	}
	status, err := proc.NewThreadProcStatus(pid, tid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}
	stat, err := proc.NewThreadProcStat(pid, tid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}

	// thread

	threadTid := status.GetPid()   // status: pid == tid
	threadPid := status.GetTgid()  // status: tgid == pid
	threadPpid := status.GetPPid() // status: ppid == ppid

	threadStartTimeNs := utils.ClockTicksToNsSinceBootTime(stat.StartTime)
	threadHash := utils.HashTaskID(uint32(threadTid), threadStartTimeNs)
	thread := pt.GetOrCreateThreadByHash(threadHash)
	threadInfo := thread.GetInfo()
	threadInfo.SetFeed(
		TaskInfoFeed{
			Tid:         int(status.GetPid()),    // status: pid == tid
			Pid:         int(status.GetTgid()),   // status: tgid == pid
			PPid:        int(status.GetPPid()),   // status: ppid == ppid
			NsTid:       int(status.GetNsPid()),  // status: nspid == nspid
			NsPid:       int(status.GetNsTgid()), // status: nstgid == nspid
			NsPPid:      int(status.GetNsPPid()), // status: nsppid == nsppid
			Uid:         -1,                      // do not change the parent UID
			Gid:         -1,                      // do not change the parent GID
			StartTimeNS: threadStartTimeNs,
		},
	)

	// thread group leader (leader tid is the same as the thread's pid, so we can find it)

	leader, err := getProcessByPID(pt, threadPid)
	if err == nil {
		leader.AddThread(threadHash) // threads associated with the leader (not parent)
		leaderHash := leader.GetHash()
		thread.SetLeaderHash(leaderHash) // same
	}

	// parent (real process, parent of all threads)

	parent, err := getProcessByPID(pt, threadPpid)
	if err == nil {
		thread.SetParentHash(parent.GetHash()) // all threads have the same parent
	}

	return nil
}

// dealWithProcFsEntry deals with a process from procfs.
func dealWithProcFsEntry(pt *ProcessTree, givenPid int) error {
	_, err := os.Stat(fmt.Sprintf("/proc/%v", givenPid))
	if os.IsNotExist(err) {
		return errfmt.Errorf("could not find process %v", givenPid)
	}

	err = dealWithProc(pt, givenPid) // run for the given process
	if err != nil {
		if debugMsgs {
			logger.Debugw("dealWithProc", "pid", givenPid, "err", err)
		}
		return err
	}

	taskPath := fmt.Sprintf("/proc/%v/task", givenPid)
	taskDirs, err := os.ReadDir(taskPath)
	if err != nil {
		return err
	}
	for _, taskDir := range taskDirs {
		if !taskDir.IsDir() {
			continue
		}
		tid, err := strconv.Atoi(taskDir.Name())
		if err != nil {
			continue
		}

		err = dealWithThread(pt, givenPid, tid) // run for all threads of the given process
		if err != nil {
			if debugMsgs {
				logger.Debugw("dealWithThread", "pid", givenPid, "tid", tid, "err", err)
			}
			continue
		}
	}

	return nil
}
