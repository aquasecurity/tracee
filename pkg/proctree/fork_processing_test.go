package proctree

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestProcessTree_ProcessFork(t *testing.T) {
	const pid = 22482
	const ppid = 22447
	shCtime := time.Unix(0, 1639044471927000000)
	forkTime := time.Unix(0, 1639044471927303690)
	beforeEventTime := forkTime.Add(1000 * time.Nanosecond) // The event received before, but fork is the first event from the kernel
	const nsPid = 3
	const nsPpid = 2
	const threadId = pid
	const threadNsId = nsPid
	const secondThreadId = pid + 1
	const secondThreadNsId = nsPid + 1
	const threadName = "sh"
	earlyExecInfo := procExecInfo{
		Cmd: []string{"sh", "-c", "ls"},
		ExecutionBinary: fileInfo{
			path:   "/bin/sh",
			hash:   "abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527",
			inode:  1234,
			device: 12,
			ctime:  shCtime,
		},
	}
	missingExitProcForkTime := time.Unix(0, 1639044400000000000)
	missingExitNormalEventTime := missingExitProcForkTime.Add(2000 * time.Nanosecond)
	missingExitExecTime := missingExitProcForkTime.Add(3000 * time.Nanosecond)

	processForkEvent := trace.Event{
		Timestamp:           int(forkTime.UnixNano()),
		ProcessID:           nsPpid,
		ThreadID:            nsPpid,
		ParentProcessID:     1,
		HostProcessID:       ppid,
		HostThreadID:        ppid,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         threadName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessFork),
		EventName:           "sched_process_fork",
		ArgsNum:             8,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(nsPpid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(nsPpid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(threadId)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(threadNsId)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(nsPid)},
		},
	}

	missingExitProcForkEvent := processForkEvent
	missingExitProcForkEvent.Timestamp = int(missingExitProcForkTime.UnixNano())

	threadForkEvent := trace.Event{
		Timestamp:           int(forkTime.UnixNano()),
		ProcessID:           nsPid,
		ThreadID:            nsPid,
		ParentProcessID:     nsPpid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         threadName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessFork),
		EventName:           "sched_process_fork",
		ArgsNum:             8,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(nsPid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(nsPid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(secondThreadId)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(secondThreadNsId)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(nsPid)},
		},
	}

	execEvent := trace.Event{
		Timestamp:           int(beforeEventTime.UnixNano()),
		ProcessID:           nsPid,
		ThreadID:            nsPid,
		ParentProcessID:     nsPpid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
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
				Value:   interface{}(earlyExecInfo.Cmd),
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
				Value:   interface{}(earlyExecInfo.ExecutionBinary.path),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "dev", Type: "dev_t"},
				Value:   interface{}(uint32(earlyExecInfo.ExecutionBinary.device)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "inode", Type: "unsigned long"},
				Value:   interface{}(uint64(earlyExecInfo.ExecutionBinary.inode)),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "invoked_from_kernel", Type: "int"},
				Value:   interface{}(0),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "ctime", Type: "unsigned long"},
				Value:   interface{}(uint64(earlyExecInfo.ExecutionBinary.ctime.UnixNano())),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
				Value:   interface{}(earlyExecInfo.ExecutionBinary.hash),
			},
		},
	}

	missingExitExecEvent := execEvent
	missingExitExecEvent.Timestamp = int(missingExitExecTime.UnixNano())

	normalEvent := trace.Event{
		Timestamp:           int(beforeEventTime.UnixNano()),
		ProcessID:           nsPid,
		ThreadID:            nsPid,
		ParentProcessID:     nsPpid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         threadName,
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             333,
		EventName:           "random_event",
		ArgsNum:             0,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args:                []trace.Argument{},
	}

	missingExitNormalEvent := normalEvent
	missingExitNormalEvent.Timestamp = int(missingExitNormalEventTime.UnixNano())

	type threadValues struct {
		forkTime      time.Time
		nameAfterFork string
		nsId          int
	}
	type expectedValues struct {
		forkTime      time.Time
		livingThreads map[int]threadValues
	}
	t.Run(
		"Main thread fork", func(t *testing.T) {
			testCases := []struct {
				testName string
				getTree  func() *ProcessTree
				expected expectedValues
			}{
				{
					testName: "Non existing process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
						},
					},
				},
				{
					testName: "Existing executed process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessExecEvent(&execEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
						},
					},
				},
				{
					testName: "Lost exit event - existing forked process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessForkEvent(&missingExitProcForkEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
						},
					},
				},
				{
					testName: "Lost exit event - existing completed process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessForkEvent(&missingExitProcForkEvent))
						require.NoError(t, tree.ProcessEvent(&missingExitNormalEvent))
						require.NoError(t, tree.ProcessExecEvent(&missingExitExecEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
						},
					},
				},
				{
					testName: "Existing general event process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessEvent(&normalEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
						},
					},
				},
			}
			forkEvent := processForkEvent
			for _, testCase := range testCases {
				t.Run(
					testCase.testName, func(t *testing.T) {
						tree := testCase.getTree()
						require.NoError(t, tree.ProcessForkEvent(&forkEvent))
						p, err := tree.getProcess(pid)
						require.NoError(t, err)
						assert.Equal(t, len(testCase.expected.livingThreads), len(p.getThreadsIds()))
						for livingTId, info := range testCase.expected.livingThreads {
							thread, ok := p.getThread(livingTId)
							require.True(t, ok, "thread - %d", livingTId)
							assert.Equal(t, info.forkTime, thread.getForkTime(), "thread - %d", livingTId)
							assert.Equal(t, info.nsId, thread.getNsTid(), "thread - %d", livingTId)
							assert.Equal(t, info.nameAfterFork, thread.getName(forkTime), "thread - %d", livingTId)
						}
						parent, err := tree.getProcess(forkEvent.HostProcessID)
						require.NoError(t, err)
						assert.Equal(t, forkEvent.HostProcessID, parent.getPid())
						assert.Equal(t, forkEvent.ProcessID, parent.getNsPid())
					},
				)
			}
		},
	)

	t.Run(
		"Normal thread fork", func(t *testing.T) {
			testCases := []struct {
				testName string
				getTree  func() *ProcessTree
				expected expectedValues
			}{
				{
					testName: "Non existing process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      time.Unix(0, 0),
								nameAfterFork: threadName,
								nsId:          threadNsId,
							},
							secondThreadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          secondThreadNsId,
							},
						},
					},
				},
				{
					testName: "Existing executed process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessExecEvent(&execEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: forkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      time.Unix(0, 0),
								nameAfterFork: execEvent.ProcessName,
								nsId:          threadNsId,
							},
							secondThreadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          secondThreadNsId,
							},
						},
					},
				},
				{
					testName: "Existing forked process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessForkEvent(&missingExitProcForkEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: missingExitProcForkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      missingExitProcForkTime,
								nameAfterFork: missingExitProcForkEvent.ProcessName,
								nsId:          threadNsId,
							},
							secondThreadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          secondThreadNsId,
							},
						},
					},
				},
				{
					testName: "Existing completed process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessForkEvent(&missingExitProcForkEvent))
						require.NoError(t, tree.ProcessEvent(&missingExitNormalEvent))
						require.NoError(t, tree.ProcessExecEvent(&missingExitExecEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: missingExitProcForkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      missingExitProcForkTime,
								nameAfterFork: missingExitExecEvent.ProcessName,
								nsId:          threadNsId,
							},
							secondThreadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          secondThreadNsId,
							},
						},
					},
				},
				{
					testName: "Existing general event process",
					getTree: func() *ProcessTree {
						tree, err := NewProcessTree(testsTreeConfig)
						require.NoError(t, err)
						require.NoError(t, tree.ProcessEvent(&normalEvent))
						return tree
					},
					expected: expectedValues{
						forkTime: missingExitProcForkTime,
						livingThreads: map[int]threadValues{
							threadId: {
								forkTime:      time.Unix(0, 0),
								nameAfterFork: normalEvent.ProcessName,
								nsId:          threadNsId,
							},
							secondThreadId: {
								forkTime:      forkTime,
								nameAfterFork: threadName,
								nsId:          secondThreadNsId,
							},
						},
					},
				},
			}
			forkEvent := threadForkEvent
			for _, testCase := range testCases {
				t.Run(
					testCase.testName, func(t *testing.T) {
						tree := testCase.getTree()
						require.NoError(t, tree.ProcessForkEvent(&forkEvent))
						p, err := tree.getProcess(pid)
						require.NoError(t, err)
						assert.Equal(t, len(testCase.expected.livingThreads), len(p.getThreadsIds()))
						for livingTId, info := range testCase.expected.livingThreads {
							thread, ok := p.getThread(livingTId)
							require.True(t, ok, "thread - %d", livingTId)
							assert.Equal(t, info.forkTime, thread.getForkTime(), "thread - %d", livingTId)
							assert.Equal(t, info.nsId, thread.getNsTid(), "thread - %d", livingTId)
							assert.Equal(t, info.nameAfterFork, thread.getName(forkTime), "thread - %d", livingTId)
						}
						parent, err := tree.getProcess(forkEvent.HostProcessID)
						require.NoError(t, err)
						assert.Equal(t, forkEvent.HostProcessID, parent.getPid())
						assert.Equal(t, forkEvent.ProcessID, parent.getNsPid())
					},
				)
			}
		},
	)
}
