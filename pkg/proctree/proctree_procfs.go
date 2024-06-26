package proctree

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
)

const debugMsgs = false                         // debug messages can be too verbose, so they are disabled by default
const ProcfsClockId = traceetime.CLOCK_BOOTTIME // Procfs uses jiffies, which are based on boottime

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
		pt.procfsChan = make(chan int, 1000)
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
	if givenPid != AllPIDs {
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

	startTimeNs := traceetime.ClockTicksToNsSinceBootTime(stat.StartTime)
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

	name := status.GetName()
	pid := status.GetPid()   // status: pid == tid
	tgid := status.GetTgid() // status: tgid == pid
	ppid := status.GetPPid()
	nspid := status.GetNsPid()
	nstgid := status.GetNsTgid()
	nsppid := status.GetNsPPid()
	start := stat.StartTime

	// sanity checks
	switch givenPid {
	case 0, 1: // PID 0 and 1 are special
	default:
		if name == "" || pid == 0 || tgid == 0 || ppid == 0 {
			return errfmt.Errorf("invalid process")
		}
	}

	// process hash
	startTimeNs := traceetime.ClockTicksToNsSinceBootTime(start)
	hash := utils.HashTaskID(uint32(pid), startTimeNs)

	// update tree for the given process
	process := pt.GetOrCreateProcessByHash(hash)
	procInfo := process.GetInfo()

	// check if the process info was already set (proctree might miss ppid and name)
	switch givenPid {
	case 0, 1: // PID 0 and 1 are special
	default:
		if procInfo.GetName() != "" && procInfo.GetPPid() != 0 {
			return nil
		}
	}

	procfsTimeStamp := uint64(pt.timeNormalizer.NormalizeTime(int(startTimeNs)))

	procInfo.SetFeedAt(
		TaskInfoFeed{
			Name:        name,   // command name (add "procfs+" to debug if needed)
			Tid:         pid,    // status: pid == tid
			Pid:         tgid,   // status: tgid == pid
			PPid:        ppid,   // status: ppid == ppid
			NsTid:       nspid,  // status: nspid == nspid
			NsPid:       nstgid, // status: nstgid == nspid
			NsPPid:      nsppid, // status: nsppid == nsppid
			Uid:         -1,     // do not change the parent uid
			Gid:         -1,     // do not change the parent gid
			StartTimeNS: procfsTimeStamp,
		},
		traceetime.NsSinceEpochToTime(procfsTimeStamp), // try to be the first changelog entry
	)

	// TODO: Update executable with information from /proc/<pid>/exe

	// update given process parent (if exists)
	parent, err := getProcessByPID(pt, status.GetPPid())
	if err == nil {
		parent.AddChild(hash)
		process.SetParentHash(parent.GetHash())
	}

	return nil
}

// dealWithThread deals with a thread from procfs.
func dealWithThread(pt *ProcessTree, givenPid int, givenTid int) error {
	if givenPid <= 0 {
		return errfmt.Errorf("invalid PID")
	}
	status, err := proc.NewThreadProcStatus(givenPid, givenTid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}
	stat, err := proc.NewThreadProcStat(givenPid, givenTid)
	if err != nil {
		return errfmt.Errorf("%v", err)
	}

	name := status.GetName()
	pid := status.GetPid()   // status: pid == tid
	tgid := status.GetTgid() // status: tgid == pid
	ppid := status.GetPPid()
	nspid := status.GetNsTgid()
	nstgid := status.GetNsTgid()
	nsppid := status.GetNsPPid()
	start := stat.StartTime

	// sanity checks
	if name == "" || pid == 0 || tgid == 0 || ppid == 0 {
		return errfmt.Errorf("invalid thread")
	}

	// thread hash
	startTimeNs := traceetime.ClockTicksToNsSinceBootTime(start)
	hash := utils.HashTaskID(uint32(pid), startTimeNs)

	// update tree for the given thread
	thread := pt.GetOrCreateThreadByHash(hash)
	threadInfo := thread.GetInfo()

	// check if the thread info was already set (proctree might miss ppid and name)
	if threadInfo.GetName() != "" && threadInfo.GetPPid() != 0 {
		return nil
	}

	procfsTimeStamp := uint64(pt.timeNormalizer.NormalizeTime(int(startTimeNs)))

	threadInfo.SetFeedAt(
		TaskInfoFeed{
			Name:        name,   // command name (add "procfs+" to debug if needed)
			Tid:         pid,    // status: pid == tid
			Pid:         tgid,   // status: tgid == pid
			PPid:        ppid,   // status: ppid == ppid
			NsTid:       nspid,  // status: nspid == nspid
			NsPid:       nstgid, // status: nstgid == nspid
			NsPPid:      nsppid, // status: nsppid == nsppid
			Uid:         -1,     // do not change the parent uid
			Gid:         -1,     // do not change the parent gid
			StartTimeNS: procfsTimeStamp,
		},
		traceetime.NsSinceEpochToTime(procfsTimeStamp), // try to be the first changelog entry
	)

	// thread group leader (leader tid is the same as the thread's pid, so we can find it)

	leader, err := getProcessByPID(pt, tgid)
	if err == nil {
		leader.AddThread(hash) // threads associated with the leader (not parent)
		leaderHash := leader.GetHash()
		thread.SetLeaderHash(leaderHash) // same
	}

	// parent (real process, parent of all threads)

	parent, err := getProcessByPID(pt, ppid)
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
