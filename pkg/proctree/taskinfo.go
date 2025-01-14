package proctree

import (
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/changelog"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
)

// TaskInfoFeed allows external packages to set/get multiple values of a task at once.
type TaskInfoFeed struct {
	Name        string // mutable (process name can be changed)
	Tid         int    // immutable
	Pid         int    // immutable
	PPid        int    // mutable (process can be reparented)
	NsTid       int    // immutable
	NsPid       int    // immutable
	NsPPid      int    // mutable (process can be reparented)
	Uid         int    // mutable (process uid can be changed)
	Gid         int    // mutable (process gid can be changed)
	StartTimeNS uint64 // immutable (this is a duration, in ns, since boot)
	ExitTimeNS  uint64 // immutable (this is a duration, in ns, since boot)
}

//
// Task Info
//

// TaskInfo represents a task.
type TaskInfo struct {
	feed  *changelog.Changelog[*TaskInfoFeed]
	mutex *sync.RWMutex
}

// NewTaskInfo creates a new task.
func NewTaskInfo() *TaskInfo {
	return &TaskInfo{
		feed:  changelog.NewChangelog[*TaskInfoFeed](3),
		mutex: &sync.RWMutex{},
	}
}

// NewTaskInfoFromFeed creates a new task with values from the given feed.
func NewTaskInfoNewFromFeed(feed *TaskInfoFeed) *TaskInfo {
	new := NewTaskInfo()
	new.setFeed(feed)

	return new
}

//
// Setters
//

// Multiple values at once (using a feed structure)

// SetFeed sets the values of the task from the given feed at the current time.
func (ti *TaskInfo) SetFeed(feed *TaskInfoFeed) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	ti.setFeed(feed)
}

// SetFeedAt sets the values of the task from the given feed at the given time.
func (ti *TaskInfo) SetFeedAt(feed *TaskInfoFeed, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	atFeed := ti.getFeedAt(targetTime)

	if feed.Name != "" {
		atFeed.Name = feed.Name
	}
	if feed.Tid >= 0 {
		atFeed.Tid = feed.Tid
	}
	if feed.Pid >= 0 {
		atFeed.Pid = feed.Pid
	}
	if feed.PPid >= 0 {
		atFeed.PPid = feed.PPid
	}
	if feed.NsTid >= 0 {
		atFeed.NsTid = feed.NsTid
	}
	if feed.NsPid >= 0 {
		atFeed.NsPid = feed.NsPid
	}
	if feed.NsPid >= 0 {
		atFeed.NsPPid = feed.NsPPid
	}
	if feed.Uid >= 0 {
		atFeed.Uid = feed.Uid
	}
	if feed.Gid >= 0 {
		atFeed.Gid = feed.Gid
	}
	if feed.StartTimeNS != 0 {
		atFeed.StartTimeNS = feed.StartTimeNS
	}
	if feed.ExitTimeNS != 0 {
		atFeed.ExitTimeNS = feed.ExitTimeNS
	}

	ti.setFeedAt(atFeed, targetTime)
}

// Single values

// SetNameAt sets the name of the task at the given time.
func (ti *TaskInfo) SetNameAt(name string, targetTime time.Time) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	feed := ti.getFeedAt(targetTime)
	feed.Name = name

	ti.setFeedAt(feed, targetTime)
}

// SetExitTime sets the exitTime of the task.
func (ti *TaskInfo) SetExitTime(exitTime uint64) {
	ti.mutex.Lock()
	defer ti.mutex.Unlock()

	exitTimestamp := traceetime.NsSinceEpochToTime(exitTime)

	feed := ti.getFeedAt(exitTimestamp)
	feed.ExitTimeNS = exitTime

	ti.setFeedAt(feed, exitTimestamp)
}

// private setters

func (ti *TaskInfo) setFeed(feed *TaskInfoFeed) {
	ti.setFeedAt(feed, time.Now())
}

func (ti *TaskInfo) setFeedAt(feed *TaskInfoFeed, targetTime time.Time) {
	ti.feed.Set(feed, targetTime)
}

//
// Getters
//

// Multiple values at once (getting a feed structure)

// GetFeed returns the values of the task as a feed.
func (ti *TaskInfo) GetFeed() TaskInfoFeed {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return *ti.getFeed() // return a copy
}

// GetFeedAt returns the values of the task as a feed at the given time.
func (ti *TaskInfo) GetFeedAt(targetTime time.Time) TaskInfoFeed {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return *ti.getFeedAt(targetTime) // return a copy
}

// Single values

// GetName returns the name of the task.
func (ti *TaskInfo) GetName() string {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().Name
}

// GetNameAt returns the name of the task at the given time.
func (ti *TaskInfo) GetNameAt(targetTime time.Time) string {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeedAt(targetTime).Name
}

// GetTid returns the tid of the task.
func (ti *TaskInfo) GetTid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().Tid
}

// GetPid returns the pid of the task.
func (ti *TaskInfo) GetPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().Pid
}

// GetNsTid returns the nsTid of the task.
func (ti *TaskInfo) GetNsTid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().NsTid
}

// GetNsPid returns the nsPid of the task.
func (ti *TaskInfo) GetNsPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().NsPid
}

// GetPPid returns the ppid of the task.
func (ti *TaskInfo) GetPPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().PPid
}

// GetPPidAt returns the ppid of the task at the given time.
func (ti *TaskInfo) GetPPidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeedAt(targetTime).PPid
}

// GetNsPPid returns the nsPPid of the task.
func (ti *TaskInfo) GetNsPPid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().NsPPid
}

// GetNsPPidAt returns the nsPPid of the task at the given time.
func (ti *TaskInfo) GetNsPPidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeedAt(targetTime).NsPPid
}

// GetUid returns the uid of the task.
func (ti *TaskInfo) GetUid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().Uid
}

// GetUidAt returns the uid of the task at the given time.
func (ti *TaskInfo) GetUidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeedAt(targetTime).Uid
}

// GetGid returns the gid of the task.
func (ti *TaskInfo) GetGid() int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().Gid
}

// GetGidAt returns the gid of the task at the given time.
func (ti *TaskInfo) GetGidAt(targetTime time.Time) int {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeedAt(targetTime).Gid
}

// GetStartTimeNS returns the start time of the task in nanoseconds since epoch
func (ti *TaskInfo) GetStartTimeNS() uint64 {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().StartTimeNS
}

// GetStartTime returns the start time of the task.
func (ti *TaskInfo) GetStartTime() time.Time {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return traceetime.NsSinceEpochToTime(ti.getFeed().StartTimeNS)
}

// GetExitTimeNS returns the exitTime of the task in nanoseconds since epoch
func (ti *TaskInfo) GetExitTimeNS() uint64 {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().ExitTimeNS
}

// GetExitTime returns the exit time of the task.
func (ti *TaskInfo) GetExitTime() time.Time {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return traceetime.NsSinceEpochToTime(ti.getFeed().ExitTimeNS)
}

// IsAlive returns true if the task has exited.
func (ti *TaskInfo) IsAlive() bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	return ti.getFeed().ExitTimeNS == 0
}

// IsAliveAt return whether the task is alive in the given time, either because it didn't start
// yet or it has exited.
func (ti *TaskInfo) IsAliveAt(targetTime time.Time) bool {
	ti.mutex.RLock()
	defer ti.mutex.RUnlock()

	feed := ti.getFeedAt(targetTime)
	exitTimeNS := feed.ExitTimeNS
	if exitTimeNS != 0 {
		if targetTime.After(traceetime.NsSinceEpochToTime(exitTimeNS)) {
			return false
		}
	}

	// If start time is not initialized it will count as 0 ns, meaning it will be before any
	// query time given.
	return !targetTime.Before(traceetime.NsSinceEpochToTime(feed.StartTimeNS))
}

// private getters

func (ti *TaskInfo) getFeed() *TaskInfoFeed {
	feed := ti.feed.GetCurrent()
	if feed == nil {
		feed = &TaskInfoFeed{}
	}

	return feed
}

func (ti *TaskInfo) getFeedAt(targetTime time.Time) *TaskInfoFeed {
	feed := ti.feed.Get(targetTime)
	if feed == nil {
		feed = &TaskInfoFeed{}
	}

	return feed
}
