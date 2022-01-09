package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const TestContainerID = "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e"

func TestProcessTree_ProcessEvent(t *testing.T) {
	pid := 22482
	ppid := 22447
	tid := pid + 1
	forkTimestamp := 1639044471927303690
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := uint(1625759227634052514)

	processForkEvent := external.Event{
		Timestamp:           forkTimestamp,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     22422,
		HostProcessID:       ppid,
		HostThreadID:        ppid,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(0)},
		},
	}
	execEvent := external.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1003,
		EventName:           "sched_process_exec",
		ArgsNum:             9,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "cmdpath", Type: "const char*"}, Value: interface{}("/bin/ls")},
			{ArgMeta: external.ArgMeta{Name: "argv", Type: "const char**"}, Value: interface{}(execCmd)},
			{ArgMeta: external.ArgMeta{Name: "env", Type: "const char**"}, Value: interface{}([]string{"HOSTNAME=aac1fa454fcd", "SHLVL=1", "HOME=/root", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/"})},
			{ArgMeta: external.ArgMeta{Name: "pathname", Type: "const char*"}, Value: interface{}(execBinaryPath)},
			{ArgMeta: external.ArgMeta{Name: "dev", Type: "dev_t"}, Value: interface{}(46)},
			{ArgMeta: external.ArgMeta{Name: "inode", Type: "unsigned long"}, Value: interface{}(576807)},
			{ArgMeta: external.ArgMeta{Name: "invoked_from_kernel", Type: "int"}, Value: interface{}(0)},
			{ArgMeta: external.ArgMeta{Name: "ctime", Type: "unsigned long"}, Value: interface{}(uint64(execBinaryCtime))},
			{ArgMeta: external.ArgMeta{Name: "sha256", Type: "const char*"}, Value: interface{}("abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527")},
		},
	}
	threadForkEvent := external.Event{
		Timestamp:           1639044471927556767,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(tid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(0)},
		},
	}
	threadExitEvent := external.Event{
		Timestamp:           1639044471928003089,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       pid,
		HostThreadID:        tid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             1,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: external.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: false},
		},
	}
	processExitEvent := external.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             1,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: external.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: true},
		},
	}

	checkProcessForksInfo := func(t *testing.T, p *processNode, exitTime int) {
		assert.Equal(t, timestamp(forkTimestamp), p.StartTime)
		assert.Contains(t, p.ThreadsExits, pid)
		assert.Equal(t, timestamp(exitTime), p.ThreadsExits[pid])
	}
	checkMissingProcessForkInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, timestamp(0), p.StartTime)
		assert.Contains(t, p.ThreadsExits, pid)
		assert.Equal(t, timestamp(0), p.ThreadsExits[pid])
	}
	checkThreadForkInfo := func(t *testing.T, p *processNode, exitTime int) {
		require.Contains(t, p.ThreadsExits, tid)
		assert.Equal(t, timestamp(exitTime), p.ThreadsExits[tid])
	}
	checkGeneralInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, pid, p.InHostIDs.Pid)
		assert.Equal(t, ppid, p.InHostIDs.Ppid)
	}
	checkExecInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, execCmd, p.Cmd)
		assert.Equal(t, execBinaryPath, p.ExecutionBinary.Path)
		assert.Equal(t, execBinaryCtime, p.ExecutionBinary.Ctime)
		assert.Equal(t, timestamp(execEvent.Timestamp), p.ExecTime)
	}
	checkNotExecedInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, []string(nil), p.Cmd)
		assert.Equal(t, "", p.ExecutionBinary.Path)
		assert.Equal(t, uint(0), p.ExecutionBinary.Ctime)
		assert.Equal(t, "", p.ExecutionBinary.Hash)
	}
	checkProcessExitInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, timestamp(processExitEvent.Timestamp), p.ThreadsExits[pid])
	}
	checkThreadExitInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, timestamp(threadExitEvent.Timestamp), p.ThreadsExits[tid])
	}
	checkProcessExitSuccess := func(t *testing.T, tree *ProcessTree) {
		tree.emptyDeadProcessesCache()
		_, err := tree.GetProcessInfo(pid)
		assert.Error(t, err)
	}

	t.Run("Ordered flows", func(t *testing.T) {
		t.Run("Ordered normal flow", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Ordered main thread exit first", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			modifiedProcessExitEvent := processExitEvent
			modifiedProcessExitEvent.Args[1].Value = interface{}(false)
			modifiedThreadExitEvent := threadExitEvent
			modifiedThreadExitEvent.Args[1].Value = interface{}(true)
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(modifiedProcessExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			err = tree.processExitEvent(modifiedThreadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
	})
	t.Run("Unordered events flows", func(t *testing.T) {
		t.Run("Unordered exec before main fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered fork thread before main fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered exit thread before thread fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, threadExitEvent.Timestamp)
			checkExecInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered exit main thread before process fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.processExitEvent(processExitEvent)
			require.Error(t, err)
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			assert.Equal(t, timestamp(0), process.ThreadsExits[pid])
			checkProcessExitSuccess(t, &tree)
		})
	})
	t.Run("Missing event flow", func(t *testing.T) {
		t.Run("Missing main fork event", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkMissingProcessForkInfo(t, process)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing exec event", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkNotExecedInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing thread fork event", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkExecInfo(t, process)
			assert.NotContains(t, process.ThreadsExits, tid)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing thread exit", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			assert.Equal(t, timestamp(0), process.ThreadsExits[pid])
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing main thread exit", func(t *testing.T) {
			tree := ProcessTree{
				processes: map[int]*processNode{},
			}
			var err error
			err = tree.ProcessEvent(processForkEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(execEvent)
			require.NoError(t, err)
			err = tree.ProcessEvent(threadForkEvent)
			require.NoError(t, err)
			process, err := tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, 0)
			checkThreadForkInfo(t, process, 0)
			checkExecInfo(t, process)
			err = tree.processExitEvent(processExitEvent)
			require.NoError(t, err)
			checkProcessExitInfo(t, process)
			assert.Equal(t, timestamp(0), process.ThreadsExits[tid])
			tree.emptyDeadProcessesCache()
			process, err = tree.GetProcessInfo(pid)
			assert.NoError(t, err)
			assert.Contains(t, process.ThreadsExits, pid)
		})
	})
}
