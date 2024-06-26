package proctree

import (
	"sync"
	"time"

	ch "github.com/aquasecurity/tracee/pkg/changelog"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
)

// TaskInfoFeed allows external packages to set/get multiple values of a task at once.
type TaskInfoFeed struct {
	Name        string
	Tid         int
	Pid         int
	PPid        int
	NsTid       int
	NsPid       int
	NsPPid      int
	Uid         int
	Gid         int
	StartTimeNS uint64
	ExitTimeNS  uint64
}

//
// Task Info
//

// TaskInfo represents a task.
type TaskInfo struct {
	name        *ch.Changelog[string] // variable (process name can be changed)
	tid         int                   // immutable
	pid         int                   // immutable
	pPid        *ch.Changelog[int]    // variable (process can be reparented)
	nsTid       int                   // immutable
	nsPid       int                   // immutable
	nsPPid      *ch.Changelog[int]    // variable (process can be reparented)
	uid         *ch.Changelog[int]    // variable (process uid can be changed)
	gid         *ch.Changelog[int]    // variable (process gid can be changed)
	startTimeNS uint64                // this is a duration, in ns, since boot (immutable)
	exitTimeNS  uint64                // this is a duration, in ns, since boot (immutable)
	mutex       *sync.RWMutex
}

// NewTaskInfo creates a new task.
func NewTaskInfo() *TaskInfo {
	return &TaskInfo{
		name: ch.NewChangelog[string](5),
		// All the folloowing values changes are currently not monitored by the process tree.
		// Hence, for now, they will only contain one value in the changelog
		pPid:   ch.NewChangelog[int](1),
		nsPPid: ch.NewChangelog[int](1),
		uid:    ch.NewChangelog[int](1),
		gid:    ch.NewChangelog[int](1),
		mutex:  &sync.RWMutex{},
	}
}

// NewTaskInfoFromFeed creates a new task with values from the given feed.
func NewTaskInfoFromFeed(feed TaskInfoFeed) *TaskInfo {
	new := NewTaskInfo()
	new.SetFeed(feed)
	return new
}

// Feed: Multiple values at once.

// SetFeed sets the values of the task from the given feed.
func (ti *TaskInfo) SetFeed(feed TaskInfoFeed) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.setFeedAt(feed, time.Now()) // set current values
}

// SetFeedAt sets the values of the task from the given feed at the given time.
func (ti *TaskInfo) SetFeedAt(feed TaskInfoFeed, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.setFeedAt(feed, targetTime) // set values at the given time
}

func (ti *TaskInfo) setFeedAt(feed TaskInfoFeed, targetTime time.Time) {
	if feed.Name != "" {
		ti.name.Set(feed.Name, targetTime)
	}
	if feed.Tid >= 0 {
		ti.tid = feed.Tid
	}
	if feed.Pid >= 0 {
		ti.pid = feed.Pid
	}
	if feed.PPid >= 0 {
		ti.pPid.Set(feed.PPid, targetTime)
	}
	if feed.NsTid >= 0 {
		ti.nsTid = feed.NsTid
	}
	if feed.NsPid >= 0 {
		ti.nsPid = feed.NsPid
	}
	if feed.NsPid >= 0 {
		ti.nsPPid.Set(feed.NsPid, targetTime)
	}
	if feed.Uid >= 0 {
		ti.uid.Set(feed.Uid, targetTime)
	}
	if feed.Gid >= 0 {
		ti.gid.Set(feed.Gid, targetTime)
	}
	if feed.StartTimeNS != 0 {
		ti.startTimeNS = feed.StartTimeNS
	}
	if feed.ExitTimeNS != 0 {
		ti.exitTimeNS = feed.ExitTimeNS
	}
}

// GetFeed returns the values of the task as a feed.
func (ti *TaskInfo) GetFeed() TaskInfoFeed {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.getFeedAt(time.Now()) // return current values
}

// GetFeedAt returns the values of the task as a feed at the given time.
func (ti *TaskInfo) GetFeedAt(targetTime time.Time) TaskInfoFeed {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.getFeedAt(targetTime) // return values at the given time
}

func (ti *TaskInfo) getFeedAt(targetTime time.Time) TaskInfoFeed {
	return TaskInfoFeed{
		Name:        ti.name.Get(targetTime),
		Tid:         ti.tid,
		Pid:         ti.pid,
		PPid:        ti.pPid.Get(targetTime),
		NsTid:       ti.nsTid,
		NsPid:       ti.nsPid,
		NsPPid:      ti.nsPPid.Get(targetTime),
		Uid:         ti.uid.Get(targetTime),
		Gid:         ti.gid.Get(targetTime),
		StartTimeNS: ti.startTimeNS,
		ExitTimeNS:  ti.exitTimeNS,
	}
}

// Setters

// SetName sets the name of the task.
func (ti *TaskInfo) SetName(name string) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.name.Set(name, time.Now())
}

// SetNameAt sets the name of the task at the given time.
func (ti *TaskInfo) SetNameAt(name string, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.name.Set(name, targetTime)
}

// SetTid sets the tid of the task.
func (ti *TaskInfo) SetTid(tid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.tid = tid
}

// SetPid sets the pid of the task.
func (ti *TaskInfo) SetPid(pid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.pid = pid
}

// SetNsTid sets the nsTid of the task.
func (ti *TaskInfo) SetNsTid(nsTid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.nsTid = nsTid
}

// SetNsPid sets the nsPid of the task.
func (ti *TaskInfo) SetNsPid(nsPid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.nsPid = nsPid
}

// SetStartTimeNS sets the startTimeNS of the task.
func (ti *TaskInfo) SetStartTimeNS(startTimeNS uint64) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.startTimeNS = startTimeNS
}

// SetExitTime sets the exitTime of the task.
func (ti *TaskInfo) SetExitTime(exitTime uint64) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.exitTimeNS = exitTime
}

// SetPPid sets the ppid of the task.
func (ti *TaskInfo) SetPPid(pPid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.pPid.Set(pPid, time.Now())
}

// SetPPidAt sets the ppid of the task at the given time.
func (ti *TaskInfo) SetPPidAt(pPid int, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.pPid.Set(pPid, targetTime)
}

// SetNsPPid sets the nsppid of the task.
func (ti *TaskInfo) SetNsPPid(nsPPid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.nsPPid.Set(nsPPid, time.Now())
}

// SetNsPPidAt sets the nsppid of the task at the given time.
func (ti *TaskInfo) SetNsPPidAt(nsPPid int, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.nsPPid.Set(nsPPid, targetTime)
}

// SetUid sets the uid of the task.
func (ti *TaskInfo) SetUid(uid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.uid.Set(uid, time.Now())
}

// SetUidAt sets the uid of the task at the given time.
func (ti *TaskInfo) SetUidAt(uid int, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.uid.Set(uid, targetTime)
}

// SetGid sets the gid of the task.
func (ti *TaskInfo) SetGid(gid int) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.gid.Set(gid, time.Now())
}

// SetGidAt sets the gid of the task at the given time.
func (ti *TaskInfo) SetGidAt(gid int, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()
	ti.gid.Set(gid, targetTime)
}

// Getters

// GetName returns the name of the task.
func (ti *TaskInfo) GetName() string {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.name.GetCurrent()
}

// GetNameAt returns the name of the task at the given time.
func (ti *TaskInfo) GetNameAt(targetTime time.Time) string {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.name.Get(targetTime)
}

// GetTid returns the tid of the task.
func (ti *TaskInfo) GetTid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.tid
}

// GetPid returns the pid of the task.
func (ti *TaskInfo) GetPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.pid
}

// GetNsTid returns the nsTid of the task.
func (ti *TaskInfo) GetNsTid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.nsTid
}

// GetNsPid returns the nsPid of the task.
func (ti *TaskInfo) GetNsPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.nsPid
}

// GetPPid returns the ppid of the task.
func (ti *TaskInfo) GetPPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.pPid.GetCurrent()
}

// GetPPidAt returns the ppid of the task at the given time.
func (ti *TaskInfo) GetPPidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.pPid.Get(targetTime)
}

// GetNsPPid returns the nsPPid of the task.
func (ti *TaskInfo) GetNsPPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.nsPPid.GetCurrent()
}

// GetNsPPidAt returns the nsPPid of the task at the given time.
func (ti *TaskInfo) GetNsPPidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.nsPPid.Get(targetTime)
}

// GetUid returns the uid of the task.
func (ti *TaskInfo) GetUid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.uid.GetCurrent()
}

// GetUidAt returns the uid of the task at the given time.
func (ti *TaskInfo) GetUidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.uid.Get(targetTime)
}

// GetGid returns the gid of the task.
func (ti *TaskInfo) GetGid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.gid.GetCurrent()
}

// GetGidAt returns the gid of the task at the given time.
func (ti *TaskInfo) GetGidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.gid.Get(targetTime)
}

// GetStartTimeNS returns the start time of the task in nanoseconds since epoch
func (ti *TaskInfo) GetStartTimeNS() uint64 {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.startTimeNS
}

// GetStartTime returns the start time of the task.
func (ti *TaskInfo) GetStartTime() time.Time {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return traceetime.NsSinceEpochToTime(ti.startTimeNS)
}

// GetExitTimeNS returns the exitTime of the task in nanoseconds since epoch
func (ti *TaskInfo) GetExitTimeNS() uint64 {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.exitTimeNS
}

// GetExitTime returns the exit time of the task.
func (ti *TaskInfo) GetExitTime() time.Time {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return traceetime.NsSinceEpochToTime(ti.exitTimeNS)
}

// IsAlive returns true if the task has exited.
func (ti *TaskInfo) IsAlive() bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	return ti.exitTimeNS == 0
}

// IsAliveAt return whether the task is alive in the given time, either because it didn't start
// yet or it has exited.
func (ti *TaskInfo) IsAliveAt(targetTime time.Time) bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()
	if ti.exitTimeNS != 0 {
		if targetTime.After(traceetime.NsSinceEpochToTime(ti.exitTimeNS)) {
			return false
		}
	}
	// If start time is not initialized it will count as 0 ns, meaning it will be before any
	// query time given.
	if targetTime.Before(traceetime.NsSinceEpochToTime(ti.startTimeNS)) {
		return false
	}
	return true
}
