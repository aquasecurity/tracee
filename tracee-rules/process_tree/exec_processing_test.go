package process_tree

import (
	"github.com/RoaringBitmap/roaring"
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
		expectedProcess processNode
	}{
		{
			testName: "empty tree",
			initialTree: ProcessTree{
				processes: map[int]*processNode{},
			},
			expectedProcess: processNode{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ProcessName: execEvent.ProcessName,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				ContainerID: TestContainerID,
				StartTime:   0,
				Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Executed)),
			},
		},
		{
			testName: "Forked event executed",
			initialTree: ProcessTree{
				processes: map[int]*processNode{
					execEvent.HostProcessID: &processNode{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "bash",
						Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked)),
						ThreadsExits: map[int]timestamp{
							execEvent.HostProcessID: timestamp(0),
						},
					},
				},
			},
			expectedProcess: processNode{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				Cmd: execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				ContainerID: TestContainerID,
				StartTime:   100000000,
				Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "Double execve process",
			initialTree: ProcessTree{
				processes: map[int]*processNode{
					execEvent.HostProcessID: &processNode{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "sleep",
						Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
						ExecutionBinary: types.BinaryInfo{
							Path:  "/bin/sleep",
							Ctime: 100,
						},
						ThreadsExits: map[int]timestamp{
							execEvent.HostProcessID: timestamp(0),
						},
					},
				},
			},
			expectedProcess: processNode{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				StartTime:   100000000,
				Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "General event generate process",
			initialTree: ProcessTree{
				processes: map[int]*processNode{
					execEvent.HostProcessID: &processNode{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						ProcessName: execEvent.ProcessName,
						Status:      *roaring.BitmapOf(uint32(types.GeneralCreated)),
						ThreadsExits: map[int]timestamp{
							execEvent.HostProcessID: timestamp(0),
						},
					},
				},
			},
			expectedProcess: processNode{
				InHostIDs: types.ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: types.ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: types.BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
				},
				Status:      *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			require.NoError(t, testCase.initialTree.processExecEvent(execEvent))
			execProcess, err := testCase.initialTree.GetProcessInfo(execEvent.HostThreadID)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedProcess.Cmd, execProcess.Cmd)
			assert.Equal(t, testCase.expectedProcess.ProcessName, execProcess.ProcessName)
			assert.Equal(t, testCase.expectedProcess.ContainerID, execProcess.ContainerID)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Pid, execProcess.InHostIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Ppid, execProcess.InHostIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Pid, execProcess.InContainerIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Ppid, execProcess.InContainerIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.StartTime, execProcess.StartTime)
			assert.Equal(t, testCase.expectedProcess.Status, execProcess.Status)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Path, execProcess.ExecutionBinary.Path)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Ctime, execProcess.ExecutionBinary.Ctime)
		})
	}
}
