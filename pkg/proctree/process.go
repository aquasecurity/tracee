package proctree

import (
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// processNode is a node in the process tree representing a process.
// Its purpose is to keep the information of the process, and the connections to other processes
// and threads nodes.
// The current implementation is using mutex as a big lock for all fields except for the pid and
// creationTime, so all internal members are assumed to be protected by it (so are not necessarily
// thread-safe types).
// However, this type is not thread-safe. It contains a mutex for the user of the struct to handle
// it when reading and writing to it. The thread-safety responsibility is on the user.
type processNode struct {
	// TODO: Add information about the processes like opened files,
	//  network activities (like TCP connections), argv, environment variables,
	//  loader and interpreter
	pid            int
	creationTime   int
	nsPid          int
	userId         int
	containerId    string
	genInfoLock    sync.Once
	execInfo       *types.TimeSeries[procExecInfo]
	forkTime       time.Time
	exitTime       time.Time
	parentProcess  *processNode
	childProcesses map[int]*processNode
	threads        map[int]*threadNode
	mutex          sync.RWMutex // Protection on all accesses to the process, except for PID reading
}

type fileInfo struct {
	path   string
	hash   string // TODO: should we call it SHA256 or Hash?
	inode  uint
	device uint
	ctime  time.Time
}

// procExecInfo is the information about a process which is changed upon execution
type procExecInfo struct {
	Cmd             []string
	ExecutionBinary fileInfo
}

func newProcessNode(pid int) (*processNode, error) {
	return &processNode{
		pid:            pid,
		forkTime:       time.Unix(0, 0),
		exitTime:       time.Unix(0, 0),
		creationTime:   int(time.Now().UnixNano()),
		threads:        make(map[int]*threadNode),
		childProcesses: make(map[int]*processNode),
		execInfo: types.NewTimeSeries[procExecInfo](procExecInfo{
			ExecutionBinary: fileInfo{ctime: time.Unix(0, 0)},
		}),
	}, nil
}

// export create a shallow copy of the node's info which is relevant to the given time
func (p *processNode) export(quertTime time.Time) ProcessInfo {
	var childrenIds []int
	var threadIds []int
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	for _, child := range p.getChildren() {
		child.mutex.RLock()
		if child.isAlive(quertTime) {
			childrenIds = append(childrenIds, child.getPid())
		}
		child.mutex.RUnlock()
	}
	for _, tnode := range p.getThreads() {
		tnode.mutex.RLock()
		if tnode.isAlive(quertTime) {
			threadIds = append(threadIds, tnode.getTid())
		}
		tnode.mutex.RUnlock()
	}
	parentId := 0
	parent := p.getParent()
	if parent != nil {
		parent.mutex.RLock()
		parentId = parent.getPid()
		parent.mutex.RUnlock()
	}

	execInfo := p.getExecInfo(quertTime)
	execBinary := FileInfo{
		Path:   execInfo.ExecutionBinary.path,
		Hash:   execInfo.ExecutionBinary.hash,
		Inode:  execInfo.ExecutionBinary.inode,
		Device: execInfo.ExecutionBinary.device,
		Ctime:  execInfo.ExecutionBinary.ctime,
	}

	return ProcessInfo{
		Pid:               p.getPid(),
		NsPid:             p.getNsPid(),
		Ppid:              parentId,
		UserId:            p.getUserId(),
		ContainerId:       p.getContainerId(),
		Cmd:               execInfo.Cmd,
		ExecutionBinary:   execBinary,
		StartTime:         p.getForkTime(),
		ExecTime:          p.getExecTime(quertTime),
		ExitTime:          p.getExitTime(),
		ThreadsIds:        threadIds,
		ChildProcessesIds: childrenIds,
		IsAlive:           p.isAlive(quertTime),
	}
}

// setGeneralInfoFromEventOnce fill the general info of the process (information
// of the event given by every process received from it) in a way that it is filled
// only once in an efficient way to reduce performance penalty.
// This method uses the process lock to reduce unnecessary locking if not needed. Make sure to unlock
// the lock before using this.
func (p *processNode) setGeneralInfoFromEventOnce(event *trace.Event) {
	p.genInfoLock.Do(
		func() {
			p.mutex.Lock()
			p.fillGeneralInfo(
				event.ProcessID,
				event.UserID,
				event.ContainerID,
			)
			p.mutex.Unlock()
		},
	)
}

// setGeneralInfoOnceUnprotected is used to fill general information of a process
// only once, but when the information cannot be retrieved from an event like
// with setGeneralInfoFromEventOnce.
// This method is not protected by locks.
func (p *processNode) setGeneralInfoOnceUnprotected(
	nsPid int,
	userId int,
	containerId string,
) {
	p.genInfoLock.Do(
		func() {
			p.fillGeneralInfo(
				nsPid,
				userId,
				containerId,
			)
		},
	)
}

// fillGeneralInfo is a util function to fill general information in process node.
// General information is an information that resides in every event from a process.
// As such, this information should only be updated once (unless it is changeable).
func (p *processNode) fillGeneralInfo(
	nsPid int,
	userId int,
	containerId string,
) {
	p.setUserId(userId)
	p.setContainerId(containerId)
	p.setNsPid(nsPid)
}

// addThreadBasic add the thread to the process node if it does not exist.
// The function also tries to synchronize the thread exit time with the process if filled after
// process exit.
// This function *does not* add the thread to the process tree, so it should be added afterward.
func (p *processNode) addThreadBasic(tid int) (*threadNode, error) {
	t, exist := p.getThread(tid)
	if exist {
		return t, nil
	}
	var err error
	t, err = newThreadNode(tid)
	if err != nil {
		return nil, err
	}
	// Update thread exit time to match process if process exited
	t.setExitTime(p.getExitTime())
	t.connectToProcess(p)
	p.connectToThread(t)
	return t, nil
}

// isAlive return if the process is alive at the given moment, according to existing information
// of the node.
func (p *processNode) isAlive(checkTime time.Time) bool {
	exitTime := p.getExitTime()
	if exitTime.UnixNano() == 0 {
		return true
	}
	if checkTime.After(exitTime) || checkTime.Equal(exitTime) {
		return false
	}
	forkTime := p.getForkTime()
	return checkTime.After(forkTime) || checkTime.Equal(forkTime)
}

// setExitTime sets the process's exit time
func (p *processNode) setExitTime(exitTime time.Time) {
	p.exitTime = exitTime
}

// setDefaultExitTime sets the process's exit time if it's not initialized
func (p *processNode) setDefaultExitTime(exitTime time.Time) {
	if p.exitTime.UnixNano() == 0 {
		p.exitTime = exitTime
	}
}

// exited return if the process exit was received
func (p *processNode) exited() bool {
	return p.getExitTime().UnixNano() != 0
}

// getExitTime return the process's exit time
func (p *processNode) getExitTime() time.Time {
	return p.exitTime
}

// setForkTime sets the process's fork time
func (p *processNode) setForkTime(forkTime time.Time) {
	p.forkTime = forkTime
}

// setDefaultForkTime sets the process's fork time if it's not initialized
func (p *processNode) setDefaultForkTime(forkTime time.Time) {
	if p.forkTime.UnixNano() == 0 {
		p.forkTime = forkTime
	}
}

// getForkTime return the process's fork time
func (p *processNode) getForkTime() time.Time {
	return p.forkTime
}

// fillExecInfo add execution information to the process from raw format
func (p *processNode) fillExecInfo(
	binary fileInfo,
	cmd []string,
	execTime time.Time,
) {
	p.setExecInfo(
		execTime, procExecInfo{
			Cmd:             cmd,
			ExecutionBinary: binary,
		},
	)
}

// setExecInfo add execution information to the process
func (p *processNode) setExecInfo(execTime time.Time, info procExecInfo) {
	execState := types.State[procExecInfo]{
		StartTime: execTime,
		Val:       info,
	}
	p.execInfo.AddState(execState)
}

// setDefaultExecInfo change the execution information assumed for the process before its first
// execution received.
func (p *processNode) setDefaultExecInfo(info procExecInfo) {
	p.execInfo.ChangeDefault(info)
}

// getExecInfo return the execution information relevant to given time
func (p *processNode) getExecInfo(relevantTime time.Time) procExecInfo {
	return p.execInfo.Get(relevantTime)
}

// getExecTime return the last execution time before the given one
func (p *processNode) getExecTime(relevantTime time.Time) time.Time {
	state := p.execInfo.GetState(relevantTime)
	return state.StartTime
}

// disconnectFromParent remove reference to parent process
func (p *processNode) disconnectFromParent() {
	p.parentProcess = nil
}

// disconnectFromThreads remove the references to all the threads
func (p *processNode) disconnectFromThreads() {
	maps.Clear(p.threads)
}

// disconnectChild remove reference to given child
func (p *processNode) disconnectChild(childToDisconnect *processNode) {
	delete(p.childProcesses, childToDisconnect.getPid())
}

// connectParent add given process as the parent process of the current one
func (p *processNode) connectParent(parent *processNode) {
	p.parentProcess = parent
}

// connectChild add given process as the child process of the current one
func (p *processNode) connectChild(child *processNode) {
	p.childProcesses[child.getPid()] = child
}

// This doesn't have to be protected by mutex, as the process Id shouldn't change after creation
func (p *processNode) getPid() int {
	return p.pid
}

// getNsPid return the PID of the process in its PID namespace
func (p *processNode) getNsPid() int {
	return p.nsPid
}

// setNsPid set the PID of the process in its namespace to given one
func (p *processNode) setNsPid(nsId int) {
	p.nsPid = nsId
}

// getContainerId return the ID of the container in which the process resides
func (p *processNode) getContainerId() string {
	return p.containerId
}

// setContainerId set the ID of the container in which the process resides
func (p *processNode) setContainerId(containerId string) {
	p.containerId = containerId
}

// getUserId return the ID of the user owning the process
func (p *processNode) getUserId() int {
	return p.userId
}

// setUserId set the ID of the user owning the process
func (p *processNode) setUserId(userId int) {
	p.userId = userId
}

// getThread return the thread with given TID if is a registered thread of the process
func (p *processNode) getThread(tid int) (*threadNode, bool) {
	thread, ok := p.threads[tid]
	return thread, ok
}

// connectToThread add reference to given thread as a thread of the current process
func (p *processNode) connectToThread(thread *threadNode) {
	p.threads[thread.getTid()] = thread
}

// disconnectThread remove the reference to given thread from the current process
func (p *processNode) disconnectThread(thread *threadNode) {
	delete(p.threads, thread.getTid())
}

// getThreads return all the registered threads of current process
func (p *processNode) getThreads() []*threadNode {
	return maps.Values(p.threads)
}

// getThreadsIds return the TIDs of all registered thread of current process
func (p *processNode) getThreadsIds() []int {
	return maps.Keys(p.threads)
}

// getChild return the child process with given PID if registered as a child of the current process
func (p *processNode) getChild(pid int) (*processNode, bool) {
	child, ok := p.childProcesses[pid]
	return child, ok
}

// getChildren return all registered children processes of current process
func (p *processNode) getChildren() []*processNode {
	return maps.Values(p.childProcesses)
}

// amountOfChildren return the amount of processes registered as children of current process
func (p *processNode) amountOfChildren() int {
	return len(p.childProcesses)
}

// hasChildren return if the current process has children registered to it
func (p *processNode) hasChildren() bool {
	return p.amountOfChildren() != 0
}

// getParent return the parent process of current one if one was registered
func (p *processNode) getParent() *processNode {
	return p.parentProcess
}

// GetUniqueId return a unique ID to identify the process by
func (p *processNode) GetUniqueId() nodeUniqueId {
	return nodeUniqueId{
		id:         p.getPid(),
		uniqueTime: p.creationTime,
	}
}

// DisconnectNode remove all references from current node to other nodes, and vice versa
func (p *processNode) DisconnectNode() {
	p.mutex.RLock()
	threads := p.getThreads()
	parent := p.getParent()
	children := p.getChildren()
	p.mutex.RUnlock()

	p.mutex.Lock()
	p.disconnectFromParent()
	p.disconnectFromThreads()
	p.disconnectFromThreads()
	p.mutex.Unlock()

	if parent != nil {
		parent.mutex.Lock()
		parent.disconnectChild(p)
		parent.mutex.Unlock()
	}

	for _, childProcess := range children {
		childProcess.mutex.RLock()
		childParentProcess := childProcess.getParent()
		childProcess.mutex.RUnlock()
		if childParentProcess == p {
			childProcess.mutex.Lock()
			childProcess.disconnectFromParent()
			childProcess.mutex.Unlock()
		}
	}

	for _, thread := range threads {
		thread.mutex.Lock()
		thread.disconnectFromProcess()
		thread.mutex.Unlock()
	}
}
