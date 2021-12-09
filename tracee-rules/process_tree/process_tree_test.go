package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProcessTree_ProcessExec(t *testing.T) {
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := 1625759227634052514
	execEvent := external.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       22482,
		HostThreadID:        22482,
		HostParentProcessID: 22447,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e",
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
			{ArgMeta: external.ArgMeta{Name: "ctime", Type: "unsigned long"}, Value: interface{}(execBinaryCtime)},
			{ArgMeta: external.ArgMeta{Name: "sha256", Type: "const char*"}, Value: interface{}("abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527")},
		},
	}
	tree := ProcessTree{
		map[string]*ContainerProcessTree{
			execEvent.ContainerID: {
				tree: map[int]*ProcessInfo{
					execEvent.HostProcessID: {},
				},
			},
		},
	}
	require.NoError(t, tree.ProcessExec(execEvent))
	execProcess, err := tree.GetProcessInfo(execEvent.ContainerID, execEvent.HostThreadID)
	require.NoError(t, err)
	assert.Equal(t, execCmd, execProcess.Cmd)
	assert.Equal(t, execBinaryPath, execProcess.ExecutionBinary.Path)
	assert.Equal(t, execBinaryCtime, execProcess.ExecutionBinary.Ctime)
}

func TestProcessTree_ProcessFork(t *testing.T) {
	forkEvent := external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     22422,
		HostProcessID:       22447,
		HostThreadID:        22447,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e",
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: 22447},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: 0},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: 22482},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: 0},
		},
	}
	tree := ProcessTree{
		map[string]*ContainerProcessTree{},
	}
	require.NoError(t, tree.ProcessFork(forkEvent))
	_, err := tree.GetProcessInfo(forkEvent.ContainerID, forkEvent.HostThreadID)
	assert.NoError(t, err)
}

func TestProcessTree_ProcessExit(t *testing.T) {
	exitEvent := external.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       22482,
		HostThreadID:        22482,
		HostParentProcessID: 22447,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		ContainerID:         "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e",
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             1,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
		},
	}
	tree := ProcessTree{
		map[string]*ContainerProcessTree{
			exitEvent.ContainerID: {
				tree: map[int]*ProcessInfo{
					exitEvent.HostProcessID: {IsAlive: true},
				},
			},
		},
	}
	_, err := tree.GetProcessInfo(exitEvent.ContainerID, exitEvent.HostThreadID)
	require.NoError(t, err)
	require.NoError(t, tree.ProcessExit(exitEvent))
	_, err = tree.GetProcessInfo(exitEvent.ContainerID, exitEvent.HostThreadID)
	assert.ErrorIs(t, fmt.Errorf("no container with given ID is recorded"), err)
}
