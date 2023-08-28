package proctree

import (
	"fmt"
	"os"
	"strconv"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

// FeedFromProcFS feeds the process tree with data from procfs.
func (pt *ProcessTree) FeedFromProcFS() error {
	procDir := "/proc"

	// getProcessByPID returns a process by its PID.
	getProcessByPID := func(pid int) (*Process, error) {
		if pid <= 0 {
			return nil, errfmt.Errorf("invalid PID")
		}
		status, err := proc.NewProcStatus(pid)
		if err != nil {
			return nil, errfmt.Errorf("%v", err)
		}
		stat, err := proc.NewProcStat(pid)
		if err != nil {
			return nil, errfmt.Errorf("%v", err)
		}

		startTimeNs := utils.ClockTicksToNsSinceBootTime(stat.StartTime)
		hash := utils.HashTaskID(uint32(status.GetPid()), startTimeNs) // status pid == tid

		return pt.GetOrCreateProcessByHash(hash), nil
	}

	// dealWithProc deals with a process from procfs.
	dealWithProc := func(pid int) error {
		if pid <= 0 {
			return errfmt.Errorf("invalid PID")
		}
		status, err := proc.NewProcStatus(pid)
		if err != nil {
			return errfmt.Errorf("%v", err)
		}
		stat, err := proc.NewProcStat(pid)
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
				Tid:         int(status.GetPid()),    // status: pid == tid
				Pid:         int(status.GetTgid()),   // status: tgid == pid
				PPid:        int(status.GetPPid()),   // status: ppid == ppid
				NsTid:       int(status.GetNsTgid()), // status: nstgid == nspid
				NsPid:       int(status.GetNsPid()),  // status: nspid == nspid
				NsPPid:      int(status.GetNsPPid()), // status: nsppid == nsppid
				Uid:         -1,                      // do not change the parent UID
				Gid:         -1,                      // do not change the parent GID
				StartTimeNS: startTimeNs,
			},
		)
		process.GetExecutable().SetName(status.GetName())

		// update given process parent (if exists)
		parent, err := getProcessByPID(status.GetPPid())
		if err == nil {
			parent.AddChild(hash)
			process.SetParentHash(parent.GetHash())
		}

		return nil
	}

	// dealWithThread deals with a thread from procfs.
	dealWithThread := func(pid int, tid int) error {
		if pid <= 0 {
			return errfmt.Errorf("invalid PID")
		}
		if pid == tid {
			// This is a "thread group leader" and, within the proctree, the leaders are processes.
			// Main reason for this is that, whenever artifacts are generated from a thread, they
			// are associated with the process (and not the threads). This gives tracee a
			// centralized place to store all artifacts from multiple threads.
			return nil
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
				NsTid:       int(status.GetNsTgid()), // status: nstgid == nspid
				NsPid:       int(status.GetNsPid()),  // status: nspid == nspid
				NsPPid:      int(status.GetNsPPid()), // status: nsppid == nsppid
				Uid:         -1,                      // do not change the parent UID
				Gid:         -1,                      // do not change the parent GID
				StartTimeNS: threadStartTimeNs,
			},
		)

		// thread group leader (leader tid is the same as the thread's pid, so we can find it)

		leader, err := getProcessByPID(threadPid)
		if err == nil {
			leader.AddThread(threadHash) // threads associated with the leader (not parent)
			leaderHash := leader.GetHash()
			thread.SetLeaderHash(leaderHash) // same
		}

		// parent (real process, parent of all threads)

		parent, err := getProcessByPID(threadPpid)
		if err == nil {
			thread.SetParentHash(parent.GetHash()) // all threads have the same parent
		}

		return nil
	}

	// Walk the procfs tree

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

		err = dealWithProc(pid) // run for each process
		if err != nil {
			logger.Debugw("proctree from procfs (process)", "pid", pid, "err", err)
			continue
		}

		taskPath := fmt.Sprintf("/proc/%v/task", pid)
		taskDirs, err := os.ReadDir(taskPath)
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, taskDir := range taskDirs {
			if !taskDir.IsDir() {
				continue
			}
			tid, err := strconv.Atoi(taskDir.Name())
			if err != nil {
				continue
			}

			err = dealWithThread(pid, tid) // run for each processes thread
			if err != nil {
				logger.Debugw("proctree from procfs (thread)", "pid", pid, "tid", tid, "err", err)
				continue
			}
		}
	}

	return nil
}
