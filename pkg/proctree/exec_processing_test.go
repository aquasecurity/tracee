package proctree

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

var testsTreeConfig = ProcessTreeConfig{
	MaxProcesses:   200,
	MaxThreads:     200,
	MaxCacheDelete: 100,
}

func TestProcessTree_ProcessExec(t *testing.T) {
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := time.Unix(0, 1625759227634052514)
	execBinaryHash := "abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527"
	execBinaryInode := 1533
	execBinaryDevice := 2080
	execEvent := trace.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           12,
		ThreadID:            12,
		ParentProcessID:     11,
		HostProcessID:       22482,
		HostThreadID:        22482,
		HostParentProcessID: 22447,
		UserID:              17,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
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
			{
				ArgMeta: trace.ArgMeta{Name: "dev", Type: "dev_t"},
				Value:   interface{}(uint32(execBinaryDevice)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "inode", Type: "unsigned long"},
				Value:   interface{}(uint64(execBinaryInode)),
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
				Value:   interface{}(execBinaryHash),
			},
		},
	}

	forkTime := time.Unix(0, 100000000)
	forkProcName := "bash"

	earlyExecCommand := []string{"sh", "-c", "ls"}
	earlyExecBinaryPath := "/bin/sh"
	earlyExecBinaryCtime := time.Unix(0, 1625759027634052530)
	earlyExecBinaryHash := "4f291296e89b784cd35479fca606f228126e3641f5bcaee68dee36583d7c9483"
	earlyExecBinaryInode := 1772
	earlyExecBinaryDevice := 2080
	earlyExecEvent := trace.Event{
		Timestamp:           1639044471927056667,
		ProcessID:           12,
		ThreadID:            12,
		ParentProcessID:     11,
		HostProcessID:       22482,
		HostThreadID:        22482,
		HostParentProcessID: 22447,
		UserID:              17,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
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
				Value:   interface{}("/bin/sh"),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "argv", Type: "const char**"},
				Value:   interface{}(earlyExecCommand),
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
				Value:   interface{}(earlyExecBinaryPath),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "dev", Type: "dev_t"},
				Value:   interface{}(uint32(earlyExecBinaryDevice)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "inode", Type: "unsigned long"},
				Value:   interface{}(uint64(earlyExecBinaryInode)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "invoked_from_kernel", Type: "int"},
				Value:   interface{}(0),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "ctime", Type: "unsigned long"},
				Value:   interface{}(uint64(earlyExecBinaryCtime.UnixNano())),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
				Value:   interface{}(earlyExecBinaryHash),
			},
		},
	}
	testCases := []struct {
		testName           string
		getInitialTree     func() *ProcessTree
		getExpectedProcess func() *processNode
	}{
		{
			testName: "empty tree",
			getInitialTree: func() *ProcessTree {
				tree, err := NewProcessTree(testsTreeConfig)
				require.NoError(t, err)
				return tree
			},
			getExpectedProcess: func() *processNode {
				proc, err := newProcessNode(execEvent.HostProcessID)
				require.NoError(t, err)
				proc.setNsPid(execEvent.ProcessID)
				proc.setContainerId(TestContainerId)
				proc.setExecInfo(
					time.Unix(0, int64(execEvent.Timestamp)), procExecInfo{
						Cmd: execCmd,
						ExecutionBinary: fileInfo{
							path:   execBinaryPath,
							ctime:  execBinaryCtime,
							hash:   execBinaryHash,
							inode:  uint(execBinaryInode),
							device: uint(execBinaryDevice),
						},
					},
				)
				thread, err := newThreadNode(execEvent.HostThreadID)
				require.NoError(t, err)
				thread.setNsTid(execEvent.ThreadID)
				thread.setName(time.Unix(0, int64(execEvent.Timestamp)), execEvent.ProcessName)
				proc.connectToThread(thread)
				thread.connectToProcess(proc)
				return proc
			},
		},
		{
			testName: "forked then executed",
			getInitialTree: func() *ProcessTree {
				tree, err := NewProcessTree(testsTreeConfig)
				require.NoError(t, err)

				proc, err := tree.newProcessNode(execEvent.HostProcessID)
				require.NoError(t, err)
				proc.setNsPid(execEvent.ProcessID)
				proc.setContainerId(TestContainerId)
				proc.setForkTime(forkTime)
				thread, err := tree.getOrCreateProcessThreadNode(proc, execEvent.HostThreadID)
				require.NoError(t, err)
				thread.setNsTid(execEvent.ThreadID)
				thread.setName(forkTime, forkProcName)
				proc.connectToThread(thread)
				thread.connectToProcess(proc)

				return tree
			},
			getExpectedProcess: func() *processNode {
				proc, err := newProcessNode(execEvent.HostProcessID)
				require.NoError(t, err)
				proc.setNsPid(execEvent.ProcessID)
				proc.setContainerId(TestContainerId)
				proc.setExecInfo(
					time.Unix(0, int64(execEvent.Timestamp)), procExecInfo{
						Cmd: execCmd,
						ExecutionBinary: fileInfo{
							path:   execBinaryPath,
							ctime:  execBinaryCtime,
							hash:   execBinaryHash,
							inode:  uint(execBinaryInode),
							device: uint(execBinaryDevice),
						},
					},
				)
				proc.setForkTime(forkTime)
				thread, err := newThreadNode(execEvent.HostThreadID)
				require.NoError(t, err)
				thread.setNsTid(execEvent.ThreadID)
				thread.setName(time.Unix(0, int64(execEvent.Timestamp)), execEvent.ProcessName)
				proc.connectToThread(thread)
				thread.connectToProcess(proc)
				return proc
			},
		},
		{
			testName: "Double execve process",
			getInitialTree: func() *ProcessTree {
				proc, err := newProcessNode(execEvent.HostProcessID)
				require.NoError(t, err)
				proc.setNsPid(execEvent.ProcessID)
				proc.setContainerId(TestContainerId)
				proc.setForkTime(forkTime)
				thread, err := newThreadNode(execEvent.HostThreadID)
				require.NoError(t, err)
				thread.setNsTid(execEvent.ThreadID)
				thread.setName(forkTime, forkProcName)
				proc.connectToThread(thread)
				thread.connectToProcess(proc)

				tree, err := NewProcessTree(testsTreeConfig)
				require.NoError(t, err)
				require.NoError(t, tree.setProcess(proc))
				require.NoError(t, tree.setThread(thread))
				require.NoError(t, tree.ProcessExecEvent(&earlyExecEvent))
				return tree
			},
			getExpectedProcess: func() *processNode {
				proc, err := newProcessNode(execEvent.HostProcessID)
				require.NoError(t, err)
				proc.setNsPid(execEvent.ProcessID)
				proc.setContainerId(TestContainerId)
				proc.setExecInfo(
					time.Unix(0, int64(earlyExecEvent.Timestamp)), procExecInfo{
						Cmd: earlyExecCommand,
						ExecutionBinary: fileInfo{
							path:   earlyExecBinaryPath,
							ctime:  earlyExecBinaryCtime,
							hash:   earlyExecBinaryHash,
							inode:  uint(earlyExecBinaryInode),
							device: uint(earlyExecBinaryDevice),
						},
					},
				)
				proc.setExecInfo(
					time.Unix(0, int64(execEvent.Timestamp)), procExecInfo{
						Cmd: execCmd,
						ExecutionBinary: fileInfo{
							path:   execBinaryPath,
							ctime:  execBinaryCtime,
							hash:   execBinaryHash,
							inode:  uint(execBinaryInode),
							device: uint(execBinaryDevice),
						},
					},
				)
				proc.setForkTime(forkTime)
				thread, err := newThreadNode(execEvent.HostThreadID)
				require.NoError(t, err)
				thread.setNsTid(execEvent.ThreadID)
				thread.setName(forkTime, forkProcName)
				thread.setName(
					time.Unix(0, int64(earlyExecEvent.Timestamp)),
					earlyExecEvent.ProcessName,
				)
				thread.setName(time.Unix(0, int64(execEvent.Timestamp)), execEvent.ProcessName)
				proc.connectToThread(thread)
				thread.connectToProcess(proc)
				return proc
			},
		},
	}

	testTimes := []time.Time{
		forkTime,
		time.Unix(0, int64(earlyExecEvent.Timestamp)), time.Unix(0, int64(execEvent.Timestamp)),
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.testName, func(t *testing.T) {
				tree := testCase.getInitialTree()
				require.NoError(t, tree.ProcessExecEvent(&execEvent))
				resultProcess, err := tree.getProcess(execEvent.HostThreadID)
				require.NoError(t, err)
				expectedProc := testCase.getExpectedProcess()

				// Check test exec event info
				for _, time := range testTimes {
					expectedExecInfo := expectedProc.getExecInfo(time)
					resultExecInfo := resultProcess.getExecInfo(time)
					assert.ElementsMatch(t, expectedExecInfo.Cmd, resultExecInfo.Cmd, "Time - %d", time)
					assert.Equal(
						t,
						expectedExecInfo.ExecutionBinary,
						resultExecInfo.ExecutionBinary,
						"Time - %d", time,
					)
				}

				// Check general event info
				assert.Equal(t, expectedProc.getContainerId(), resultProcess.getContainerId())
				assert.Equal(t, expectedProc.getPid(), resultProcess.getPid())
				assert.Equal(t, expectedProc.getNsPid(), resultProcess.getNsPid())
				assert.Equal(t, expectedProc.getForkTime(), resultProcess.getForkTime())
				assert.Equal(t, expectedProc.getExitTime(), resultProcess.getExitTime())

				resultThreads := resultProcess.getThreads()
				expectedThreads := expectedProc.getThreads()
				assert.Equal(t, len(expectedThreads), len(resultThreads))
				for _, expectedThread := range expectedThreads {
					resultThread, ok := resultProcess.getThread(expectedThread.getTid())
					assert.True(t, ok, "tid - %d", expectedThread.getTid())
					assert.Equal(t, expectedThread.getNsTid(), resultThread.getNsTid(), "tid - %d", expectedThread.getTid())
					assert.Equal(t, expectedThread.getForkTime(), resultThread.getForkTime(), "tid - %d", expectedThread.getTid())
					assert.Equal(t, expectedThread.getExitTime(), resultThread.getExitTime(), "tid - %d", expectedThread.getTid())
					for _, time := range testTimes {
						assert.Equal(
							t,
							expectedThread.getName(time),
							expectedThread.getName(time),
							"tid - %d", expectedThread.getTid(),
						)
					}
				}
			},
		)
	}
}
