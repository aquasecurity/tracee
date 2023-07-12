package proctree

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

const TestContainerId = "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e"

func TestProcessTree_ProcessEvent(t *testing.T) {
	pid := 22482
	ppid := 22447
	tid := pid + 1
	forkTimestamp := 1639044471927303690
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := time.Unix(0, 1625759227634052514)
	execInode := uint(576807)
	execDevice := uint(47)
	mountNs := 4026532548
	pidNs := 4026532551
	processName := "ls"
	userId := 1337
	lastTimestamp := time.Unix(0, 1639044471928009089)

	processForkEvent := trace.Event{
		Timestamp:           forkTimestamp,
		ProcessID:           ppid,
		ThreadID:            ppid,
		ParentProcessID:     22422,
		HostProcessID:       ppid,
		HostThreadID:        ppid,
		HostParentProcessID: 22422,
		UserID:              userId,
		MountNS:             mountNs,
		PIDNS:               pidNs,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessFork),
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(pid)},
		},
	}
	execEvent := trace.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              userId,
		MountNS:             mountNs,
		PIDNS:               pidNs,
		ProcessName:         processName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessExec),
		EventName:           "sched_process_exec",
		ArgsNum:             9,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "cmdpath", Type: "const char*"},
				Value:   interface{}("/bin/ls"),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "argv", Type: "const char**"},
				Value:   interface{}(execCmd),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "env", Type: "const char**"},
				Value: interface{}([]string{
					"HOSTNAME=aac1fa454fcd",
					"SHLVL=1",
					"HOME=/root",
					"TERM=xterm",
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"PWD=/",
				}),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "pathname", Type: "const char*"},
				Value:   interface{}(execBinaryPath),
			},
			{ArgMeta: trace.ArgMeta{Name: "dev", Type: "dev_t"}, Value: interface{}(uint32(execDevice))},
			{
				ArgMeta: trace.ArgMeta{Name: "inode", Type: "unsigned long"},
				Value:   interface{}(uint64(execInode)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "invoked_from_kernel", Type: "int"},
				Value:   interface{}(0),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "ctime", Type: "unsigned long"},
				Value:   interface{}(uint64(execBinaryCtime.UnixNano())),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
				Value:   interface{}("abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527"),
			},
		},
	}
	threadForkEvent := trace.Event{
		Timestamp:           1639044471927556767,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              userId,
		MountNS:             mountNs,
		ProcessName:         processName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessFork),
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(pid)},
		},
	}
	threadExitEvent := trace.Event{
		Timestamp:           1639044471928003089,
		ProcessID:           pid,
		ThreadID:            tid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        tid,
		HostParentProcessID: ppid,
		UserID:              userId,
		MountNS:             mountNs,
		PIDNS:               pidNs,
		ProcessName:         processName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessExit),
		EventName:           "sched_process_exit",
		ArgsNum:             2,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: false},
		},
	}
	processExitEvent := trace.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              userId,
		MountNS:             mountNs,
		PIDNS:               pidNs,
		ProcessName:         processName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessExit),
		EventName:           "sched_process_exit",
		ArgsNum:             2,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: true},
		},
	}

	checkProcessForksInfo := func(t *testing.T, p *processNode, forkTime int, exitTime int) {
		assert.Equal(t, time.Unix(0, int64(forkTime)), p.getForkTime())
		thread, ok := p.getThread(pid)
		require.True(t, ok, "thread", pid)
		assert.Contains(t, p.getThreads(), thread)
		assert.Equal(t, time.Unix(0, int64(exitTime)), thread.getExitTime())
		assert.Equal(t, time.Unix(0, int64(forkTime)), thread.getForkTime())
	}
	checkMissingProcessForkInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, time.Unix(0, 0), p.getForkTime())
		thread, ok := p.getThread(pid)
		require.True(t, ok, "thread", pid)
		assert.Equal(t, time.Unix(0, 0), thread.getExitTime())
		assert.Equal(t, time.Unix(0, 0), thread.getForkTime())
	}
	checkThreadForkInfo := func(t *testing.T, p *processNode, forkTime int, exitTime int) {
		thread, ok := p.getThread(tid)
		require.True(t, ok, "thread", tid)
		assert.Contains(t, p.getThreads(), thread)
		assert.Equal(t, time.Unix(0, int64(exitTime)), thread.getExitTime())
		assert.Equal(t, time.Unix(0, int64(forkTime)), thread.getForkTime())
	}
	checkGeneralInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, pid, p.getPid())
		assert.Equal(t, TestContainerId, p.getContainerId())
		assert.Equal(t, userId, p.getUserId())
		parent := p.getParent()
		require.NotNil(t, parent)
		assert.Equal(t, ppid, parent.getPid())
	}
	checkExecInfo := func(t *testing.T, p *processNode) {
		execInfo := p.getExecInfo(lastTimestamp)
		assert.Equal(t, execCmd, execInfo.Cmd)
		assert.Equal(t, execBinaryPath, execInfo.ExecutionBinary.path)
		assert.Equal(t, execBinaryCtime, execInfo.ExecutionBinary.ctime)
		assert.Equal(t, time.Unix(0, int64(execEvent.Timestamp)), p.getExecTime(lastTimestamp))
		assert.Equal(t, execInode, execInfo.ExecutionBinary.inode)
		assert.Equal(t, execDevice, execInfo.ExecutionBinary.device)
	}
	checkNotExecedInfo := func(t *testing.T, p *processNode) {
		execInfo := p.getExecInfo(lastTimestamp)
		assert.Equal(t, []string(nil), execInfo.Cmd)
		assert.Equal(t, "", execInfo.ExecutionBinary.path)
		assert.Equal(t, time.Unix(0, 0), execInfo.ExecutionBinary.ctime)
		assert.Equal(t, "", execInfo.ExecutionBinary.hash)
		assert.Equal(t, uint(0), execInfo.ExecutionBinary.inode)
		assert.Equal(t, uint(0), execInfo.ExecutionBinary.device)
	}
	checkProcessExitInfo := func(t *testing.T, p *processNode) {
		thread, ok := p.getThread(pid)
		require.True(t, ok, "thread", pid)
		assert.Equal(t, time.Unix(0, int64(processExitEvent.Timestamp)), thread.getExitTime())
		assert.True(t, thread.isAlive(time.Unix(0, int64(processForkEvent.Timestamp))))
		assert.False(t, thread.isAlive(time.Unix(0, int64(processExitEvent.Timestamp))))
	}
	checkThreadExitInfo := func(t *testing.T, p *processNode) {
		thread, ok := p.getThread(tid)
		require.True(t, ok, "thread", tid)
		assert.Equal(t, time.Unix(0, int64(threadExitEvent.Timestamp)), thread.getExitTime())
		assert.True(t, thread.isAlive(time.Unix(0, int64(threadForkEvent.Timestamp))))
		assert.False(t, thread.isAlive(time.Unix(0, int64(threadExitEvent.Timestamp))))
	}
	checkProcessExitSuccess := func(t *testing.T, tree *ProcessTree) {
		tree.emptyDeadProcessesCache()
		_, err := tree.getProcess(pid)
		assert.Error(t, err)
	}

	t.Run(
		"Ordered flows", func(t *testing.T) {
			t.Run(
				"Ordered normal flow", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Ordered main thread exit first", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					// Switch between the exit events order for this test
					var modifiedProcessExitEvent, modifiedThreadExitEvent trace.Event
					modifiedProcessExitEvent = processExitEvent
					modifiedProcessExitEvent.Args = make([]trace.Argument, 2)
					copy(modifiedProcessExitEvent.Args, processExitEvent.Args)
					modifiedProcessExitEvent.Args[1].Value = interface{}(false)
					modifiedThreadExitEvent = threadExitEvent
					modifiedThreadExitEvent.Args = make([]trace.Argument, 2)
					copy(modifiedThreadExitEvent.Args, threadExitEvent.Args)
					modifiedThreadExitEvent.Args[1].Value = interface{}(true)
					modifiedProcessExitEvent.Timestamp, modifiedThreadExitEvent.Timestamp = modifiedThreadExitEvent.Timestamp, modifiedProcessExitEvent.Timestamp

					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					require.NoError(t, tree.ProcessEvent(&modifiedProcessExitEvent))
					mainThread, ok := process.getThread(pid)
					require.True(t, ok, "thread", pid)
					assert.Equal(
						t,
						time.Unix(0, int64(modifiedProcessExitEvent.Timestamp)),
						mainThread.getExitTime(),
					)
					require.NoError(t, tree.ProcessEvent(&modifiedThreadExitEvent))
					forkedThread, ok := process.getThread(tid)
					require.True(t, ok, "thread", tid)
					assert.Equal(
						t,
						time.Unix(0, int64(modifiedThreadExitEvent.Timestamp)),
						forkedThread.getExitTime(),
					)
					checkProcessExitSuccess(t, tree)
				},
			)
		},
	)
	t.Run(
		"Unordered events flows", func(t *testing.T) {
			t.Run(
				"Unordered exec before main fork", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkExecInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Unordered fork thread before main fork", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Unordered exit thread before thread fork", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkThreadForkInfo(
						t,
						process,
						threadForkEvent.Timestamp,
						threadExitEvent.Timestamp,
					)
					checkExecInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Unordered exit main thread before process fork", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(
						t,
						process,
						processForkEvent.Timestamp,
						processExitEvent.Timestamp,
					)
					checkThreadForkInfo(
						t,
						process,
						threadForkEvent.Timestamp,
						processExitEvent.Timestamp,
					)
					checkExecInfo(t, process)
					err = tree.ProcessEvent(&threadExitEvent)
					require.NoError(t, err)
					checkThreadExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
		},
	)
	t.Run(
		"Missing event flow", func(t *testing.T) {
			t.Run(
				"Missing main fork event", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkMissingProcessForkInfo(t, process)
					checkExecInfo(t, process)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Missing exec event", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkNotExecedInfo(t, process)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Missing thread fork event", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					assert.NotContains(t, process.getThreadsIds(), tid)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Missing thread exit", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&processExitEvent))
					checkProcessExitInfo(t, process)
					forkedThread, ok := process.getThread(tid)
					require.True(t, ok, "thread", tid)
					assert.Equal(t, time.Unix(0, int64(processExitEvent.Timestamp)), forkedThread.getExitTime())
					checkProcessExitSuccess(t, tree)
				},
			)
			t.Run(
				"Missing main thread exit", func(t *testing.T) {
					tree, err := NewProcessTree(testsTreeConfig)
					require.NoError(t, err)
					require.NoError(t, tree.ProcessEvent(&processForkEvent))
					require.NoError(t, tree.ProcessEvent(&execEvent))
					require.NoError(t, tree.ProcessEvent(&threadForkEvent))
					process, err := tree.getProcess(pid)
					assert.NoError(t, err)
					checkGeneralInfo(t, process)
					checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
					checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
					checkExecInfo(t, process)
					require.NoError(t, tree.ProcessEvent(&threadExitEvent))
					checkThreadExitInfo(t, process)
					mainThread, ok := process.getThread(pid)
					require.True(t, ok, "thread", pid)
					assert.Equal(t, time.Unix(0, 0), mainThread.getExitTime())
					tree.emptyDeadProcessesCache()
					process, err = tree.getProcess(pid)
					assert.NoError(t, err)
					assert.Contains(t, process.getThreadsIds(), pid)
				},
			)
		},
	)
}
