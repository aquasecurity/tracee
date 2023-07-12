package proctree

import (
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// threadNode is the node in the ProcessTree which represent a single thread.
// It contains all the information regrading the thread, and its connection to its process node.
// This type is not thread-safe, but contains a mutex for the user of the struct to handle it when
// reading and writing to it. It means that the responsibility for thread-safety is on the user.
// The mutex as a big lock for all fields except for the tid and creationTime, so all internal
// members are assumed to be protected by it (so are not necessarily thread-safe types).
type threadNode struct {
	tid          int
	creationTime int
	nsTid        int
	name         *types.TimeSeries[string]
	forkTime     time.Time
	exitTime     time.Time
	namespaces   NamespacesIds
	process      *processNode
	mutex        sync.RWMutex // Protection on all accesses to the thread, except for TID reading
	genInfoLock  sync.Once
}

// newThreadNode creates a new threadNode instance, with initialized values where needed.
func newThreadNode(tid int) (*threadNode, error) {
	return &threadNode{
		tid:          tid,
		forkTime:     time.Unix(0, 0),
		exitTime:     time.Unix(0, 0),
		creationTime: int(time.Now().UnixNano()),
		name:         types.NewTimeSeries[string](""),
	}, nil
}

// export create a shallow copy of the node's info which is relevant to the given time
func (t *threadNode) export(queryTime time.Time) ThreadInfo {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	process := t.getProcess()

	return ThreadInfo{
		Tid:        t.getTid(),
		NsTid:      t.getNsTid(),
		Pid:        process.getPid(),
		ForkTime:   t.getForkTime(),
		ExitTime:   t.getExitTime(),
		Namespaces: t.getNamespaces(),
		Name:       t.getName(queryTime),
		IsAlive:    t.isAlive(queryTime),
	}
}

// disconnectFromProcess remove the reference to the thread's processNode
func (t *threadNode) disconnectFromProcess() {
	t.process = nil
}

// connectToProcess add a processNode as the process of the thread.
func (t *threadNode) connectToProcess(proc *processNode) {
	t.process = proc
}

// getProcess return the thread's process
func (t *threadNode) getProcess() *processNode {
	return t.process
}

// isAlive return if the thread is alive at the given moment, according to existing information
// of the node.
func (t *threadNode) isAlive(checkTime time.Time) bool {
	exitTime := t.getExitTime()
	if exitTime.UnixNano() == 0 {
		return true
	}
	if checkTime.After(exitTime) || checkTime.Equal(exitTime) {
		return false
	}
	forkTime := t.getForkTime()
	return checkTime.After(forkTime) || checkTime.Equal(forkTime)
}

// setGeneralInfoFromEventOnce fill the general info of the thread (information
// of the thread given by every event received from it) in a way that it is filled
// only once in an efficient way to reduce performance penalty.
// This method uses the thread lock to reduce unnecessary locking if not needed. Make sure to unlock
// the lock before using this.
func (t *threadNode) setGeneralInfoFromEventOnce(
	event *trace.Event,
	defaultExitTime time.Time,
) {
	t.genInfoLock.Do(
		func() {
			t.mutex.Lock()
			t.fillGeneralInfo(
				event.ThreadID,
				event.ProcessName,
				NamespacesIds{
					Pid:   event.PIDNS,
					Mount: event.MountNS,
				},
				defaultExitTime,
			)
			t.mutex.Unlock()
		},
	)
}

// setGeneralInfoOnceUnprotected is used to fill general information of a thread
// only once, but when the information cannot be retrieved from an event like
// with setGeneralInfoFromEventOnce.
// This method is not protected by locks.
func (t *threadNode) setGeneralInfoOnceUnprotected(
	nsTid int,
	name string,
	namespaces NamespacesIds,
	defaultExitTime time.Time,
) {
	t.genInfoLock.Do(
		func() {
			t.fillGeneralInfo(
				nsTid,
				name,
				namespaces,
				defaultExitTime,
			)
		},
	)
}

// fillGeneralInfo is a util function to fill general information in thread node.
// General information is an information that resides in every event from a thread.
// As such, this information should only be updated once (unless it is changeable).
func (t *threadNode) fillGeneralInfo(
	nsTid int,
	name string,
	namespaces NamespacesIds,
	defaultExitTime time.Time,
) {
	t.setNsTid(nsTid)
	t.setDefaultName(name)
	t.setNamespaces(namespaces)
	t.setDefaultExitTime(defaultExitTime)
}

// getTid return the TID of the thread in the host.
// This doesn't have to be protected by mutex, as the process Id shouldn't change after creation
func (t *threadNode) getTid() int {
	return t.tid
}

// getNsTid return the TID of the thread in its PID namespace.
func (t *threadNode) getNsTid() int {
	return t.nsTid
}

// setNsTid set the TID of the thread in its PID namespace to the given one.
func (t *threadNode) setNsTid(nsId int) {
	t.nsTid = nsId
}

// setExitTime sets the thread's exit time
func (t *threadNode) setExitTime(exitTime time.Time) {
	t.exitTime = exitTime
}

// setDefaultExitTime sets the thread's exit time if it's not initialized
func (t *threadNode) setDefaultExitTime(exitTime time.Time) {
	if t.exitTime.UnixNano() == 0 {
		t.setExitTime(exitTime)
	}
}

// getExitTime return the thread's exit time
func (t *threadNode) getExitTime() time.Time {
	return t.exitTime
}

// setForkTime sets the thread's fork time
func (t *threadNode) setForkTime(forkTime time.Time) {
	t.forkTime = forkTime
}

// setDefaultForkTime sets the thread's fork time if it's not initialized
func (t *threadNode) setDefaultForkTime(forkTime time.Time) {
	if t.forkTime.UnixNano() == 0 {
		t.setForkTime(forkTime)
	}
}

// getForkTime return the thread's fork time
func (t *threadNode) getForkTime() time.Time {
	return t.forkTime
}

// getName return the thread's name, as it was at a given time.
// As a thread can change its name, by execve or prctl syscalls for example, the time of request
// is necessary.
func (t *threadNode) getName(relevantTime time.Time) string {
	return t.name.Get(relevantTime)
}

// setName change the name of the thread to a new one starting from a given time.
func (t *threadNode) setName(changeTime time.Time, name string) {
	nameState := types.State[string]{
		StartTime: changeTime,
		Val:       name,
	}
	t.name.AddState(nameState)
}

// setDefaultName change the name of the thread for any time in which it was not set until now.
// For example, if a thread's name changed after execution to "ls" in time 50, and its default
// name was set to "bash", for any time before 50 (for example, 42) it will still be considered
// "bash". For any time after 50, it will be considered "ls".
func (t *threadNode) setDefaultName(name string) {
	t.name.ChangeDefault(name)
}

// getNamespaces return all the namespaces of the threads.
func (t *threadNode) getNamespaces() NamespacesIds {
	return t.namespaces
}

// setNamespaces set the thread's namespaces
func (t *threadNode) setNamespaces(namespaces NamespacesIds) {
	t.namespaces = namespaces
}

// GetUniqueId return a unique ID to identify the node with, even if another thread node has the
// same TID as it.
func (t *threadNode) GetUniqueId() nodeUniqueId {
	return nodeUniqueId{
		id:         t.getTid(),
		uniqueTime: t.creationTime,
	}
}

// DisconnectNode disconnect the thread from the process and vice versa.
// Notice that this is the only method locking the mutex, because it fulfills the gcNode interface.
func (t *threadNode) DisconnectNode() {
	t.mutex.Lock()
	proc := t.getProcess()
	if proc != nil {
		proc.mutex.Lock()
		proc.disconnectThread(t)
		proc.mutex.Unlock()
	}
	t.disconnectFromProcess()
	t.mutex.Unlock()
}
