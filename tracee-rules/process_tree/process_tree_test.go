package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const TestContainerID = "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e"

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
		{
			testName: "Lost exit event process with same PID",
			initialTree: ProcessTree{
				tree: map[int]*types.ProcessInfo{
					execEvent.HostProcessID: &types.ProcessInfo{
						InHostIDs: types.ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: 1,
							Tid:  execEvent.HostThreadID,
						},
						InContainerIDs: types.ProcessIDs{
							Pid:  22,
							Ppid: 21,
							Tid:  22,
						},
						StartTime:   100,
						ProcessName: "sleep",
						Status:      types.Completed,
						ExecutionBinary: types.BinaryInfo{
							Path:  "/bin/sleep",
							Ctime: 50,
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

func TestProcessTree_ProcessFork(t *testing.T) {
	newProcessTID := 22482
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
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(22447)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(22447)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(newProcessTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(newProcessTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(0)},
		},
	}
	tree := ProcessTree{
		tree:       map[int]*types.ProcessInfo{},
		containers: map[string]*containerProcessTree{},
	}
	require.NoError(t, tree.processFork(forkEvent))
	_, err := tree.GetProcessInfo(newProcessTID)
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
		ContainerID:         TestContainerID,
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             1,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
		},
	}
	type testProcess struct {
		isAlive bool
		aErr    error
	}

	tests := []struct {
		name string
		// Each process in the list will be the father of the next process in the list
		// The last process in the list is the process that the exit event will occur in
		processes []testProcess
	}{
		{
			name: "exit of root process of container",
			processes: []testProcess{
				{
					isAlive: true,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
			},
		},
		{
			name: "exit of process with alive father",
			processes: []testProcess{
				{
					isAlive: true,
					aErr:    nil,
				},
				{
					isAlive: true,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
			},
		},
		{
			name: "exit of process with dead father which is not root",
			processes: []testProcess{
				{
					isAlive: true,
					aErr:    nil,
				},
				{
					isAlive: false,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
				{
					isAlive: true,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
			},
		},
		{
			name: "exit of process with dead father which is root",
			processes: []testProcess{
				{
					isAlive: false,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
				{
					isAlive: true,
					aErr:    fmt.Errorf("no process with given ID is recorded"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := ProcessTree{
				tree:       map[int]*types.ProcessInfo{},
				containers: map[string]*containerProcessTree{},
			}
			exitProcessIndex := len(test.processes) - 1
			// Build the container tree
			for i, tp := range test.processes {
				np := types.ProcessInfo{
					IsAlive: tp.isAlive,
					InHostIDs: types.ProcessIDs{
						Tid: exitEvent.HostThreadID - (exitProcessIndex - i),
					},
				}
				tree.tree[np.InHostIDs.Tid] = &np
				if i != 0 {
					var err error
					np.ParentProcess, err = tree.GetProcessInfo(exitEvent.HostThreadID - (len(test.processes) - i))
					require.NoError(t, err)
					np.ParentProcess.ChildProcesses = append(np.ParentProcess.ChildProcesses, &np)
				} else {
					tree.containers[TestContainerID] = &containerProcessTree{Root: &np}
				}
			}

			err := tree.processExit(exitEvent)
			require.NoError(t, err)
			// Check that all nodes removed as expected
			eLivingNodes := 0
			for i, tp := range test.processes {
				_, err = tree.GetProcessInfo(exitEvent.HostThreadID - (exitProcessIndex - i))
				assert.Equal(t, tp.aErr, err)
				if tp.isAlive && i != exitProcessIndex {
					eLivingNodes = i + 1
				}
			}
			p, err := tree.GetContainerRoot(exitEvent.ContainerID)
			if err == nil {
				rLivingChildren := countChildren(p)
				assert.NotZero(t, rLivingChildren)
				assert.Equal(t, eLivingNodes, rLivingChildren)
			} else {
				assert.Zero(t, eLivingNodes)
			}
		})
	}
}

func countChildren(p *types.ProcessInfo) int {
	c := 0
	for _, chld := range p.ChildProcesses {
		c += countChildren(chld)
	}
	return 1 + c
}

func TestProcessTree_ProcessEvent(t *testing.T) {
	tree := ProcessTree{
		containers: map[string]*containerProcessTree{},
		tree:       map[int]*types.ProcessInfo{},
	}

	ptid := 22482
	ppid := 22447
	forkTimestamp := 1639044471927303690
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := uint(1625759227634052514)

	forkEvent := external.Event{
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
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(ptid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(ptid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(0)},
		},
	}
	execEvent := external.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       ptid,
		HostThreadID:        ptid,
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
	exitEvent := external.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       ptid,
		HostThreadID:        ptid,
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
		},
	}

	err := tree.ProcessEvent(forkEvent)
	require.NoError(t, err)
	err = tree.ProcessEvent(execEvent)
	require.NoError(t, err)
	process, err := tree.GetProcessInfo(ptid)
	assert.NoError(t, err)
	assert.Equal(t, ptid, process.InHostIDs.Tid)
	assert.Equal(t, ptid, process.InHostIDs.Pid)
	assert.Equal(t, ppid, process.InHostIDs.Ppid)
	assert.Equal(t, forkTimestamp, process.StartTime)
	assert.Equal(t, execCmd, process.Cmd)
	assert.Equal(t, execBinaryPath, process.ExecutionBinary.Path)
	assert.Equal(t, execBinaryCtime, process.ExecutionBinary.Ctime)
	err = tree.processExit(exitEvent)
	require.NoError(t, err)
	_, err = tree.GetProcessInfo(ptid)
	assert.Error(t, err)
}
