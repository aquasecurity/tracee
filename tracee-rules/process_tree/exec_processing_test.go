package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
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
	testCases := []struct {
		testName        string
		initialTree     ProcessTree
		expectedProcess types.ProcessInfo
	}{
		{
			testName: "empty tree",
			initialTree: ProcessTree{
				tree:       map[int]*types.ProcessInfo{},
				containers: map[string]*containerProcessTree{},
			},
			expectedProcess: types.ProcessInfo{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
					Tid:  execEvent.HostThreadID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
					Tid:  execEvent.ThreadID,
				},
				ProcessName: execEvent.ProcessName,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				ContainerID: TestContainerID,
				StartTime:   0,
				Status:      types.Executed,
			},
		},
		{
			testName: "Forked event executed",
			initialTree: ProcessTree{
				tree: map[int]*types.ProcessInfo{
					execEvent.HostProcessID: &types.ProcessInfo{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
							Tid:  execEvent.HostThreadID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
							Tid:  execEvent.ThreadID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "bash",
						Status:      types.Forked,
					},
				},
				containers: map[string]*containerProcessTree{},
			},
			expectedProcess: types.ProcessInfo{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
					Tid:  execEvent.HostThreadID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
					Tid:  execEvent.ThreadID,
				},
				Cmd: execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				ContainerID: TestContainerID,
				StartTime:   100000000,
				Status:      types.Completed,
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "Double execve process",
			initialTree: ProcessTree{
				tree: map[int]*types.ProcessInfo{
					execEvent.HostProcessID: &types.ProcessInfo{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
							Tid:  execEvent.HostThreadID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
							Tid:  execEvent.ThreadID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "sleep",
						Status:      types.Completed,
						ExecutionBinary: types.BinaryInfo{
							Path:  "/bin/sleep",
							Ctime: 100,
						},
					},
				},
				containers: map[string]*containerProcessTree{},
			},
			expectedProcess: types.ProcessInfo{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
					Tid:  execEvent.HostThreadID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
					Tid:  execEvent.ThreadID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				StartTime:   100000000,
				Status:      types.Completed,
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "General event generate process",
			initialTree: ProcessTree{
				tree: map[int]*types.ProcessInfo{
					execEvent.HostProcessID: &types.ProcessInfo{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
							Tid:  execEvent.HostThreadID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
							Tid:  execEvent.ThreadID,
						},
						ContainerID: TestContainerID,
						ProcessName: execEvent.ProcessName,
						Status:      types.GeneralCreated,
					},
				},
				containers: map[string]*containerProcessTree{},
			},
			expectedProcess: types.ProcessInfo{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
					Tid:  execEvent.HostThreadID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
					Tid:  execEvent.ThreadID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				Status:      types.Executed,
				ProcessName: execEvent.ProcessName,
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			require.NoError(t, testCase.initialTree.processExec(execEvent))
			execProcess, err := testCase.initialTree.GetProcessInfo(execEvent.HostThreadID)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedProcess.Cmd, execProcess.Cmd)
			assert.Equal(t, testCase.expectedProcess.ProcessName, execProcess.ProcessName)
			assert.Equal(t, testCase.expectedProcess.ContainerID, execProcess.ContainerID)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Pid, execProcess.InHostIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Tid, execProcess.InHostIDs.Tid)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Ppid, execProcess.InHostIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Pid, execProcess.InContainerIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Tid, execProcess.InContainerIDs.Tid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Ppid, execProcess.InContainerIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.StartTime, execProcess.StartTime)
			assert.Equal(t, testCase.expectedProcess.Status, execProcess.Status)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Path, execProcess.ExecutionBinary.Path)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Ctime, execProcess.ExecutionBinary.Ctime)
		})
	}
}
