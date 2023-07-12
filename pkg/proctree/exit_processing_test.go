package proctree

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type testProcess struct {
	isAlive        bool
	existAfterTest bool
}

func TestProcessTree_ProcessExit(t *testing.T) {
	t.Run("Linear tree", testLinearTreeExit)
	t.Run("Exit of process with siblings", testExitWithSiblings)
	t.Run("Normal thread exit", testThreadExit)
}

// testLinearTreeExit tests multiple cases of process exit in a linear tree - tree consisting of
// only processes with a single thread and a single child.
// We expect that process exit this way will cause the process to be deleted if it has no living
// children, and delete all dead ancestors if it is deleted.
func testLinearTreeExit(t *testing.T) {
	exitEvent := getExitEvent(22482, 22482, true)

	straitTreeTests := []struct {
		name string
		// Each process in the list will be the parent of the next process in the list
		// The last process in the list is the process that the exit event will occur in
		processes []testProcess
	}{
		{
			name: "exit of root process of container",
			processes: []testProcess{
				{
					isAlive:        true,
					existAfterTest: false,
				},
			},
		},
		{
			name: "exit of process with alive parent",
			processes: []testProcess{
				{
					isAlive:        true,
					existAfterTest: true,
				},
				{
					isAlive:        true,
					existAfterTest: false,
				},
			},
		},
		{
			name: "exit of process with dead parent which is not root",
			processes: []testProcess{
				{
					isAlive:        true,
					existAfterTest: true,
				},
				{
					isAlive:        false,
					existAfterTest: false,
				},
				{
					isAlive:        true,
					existAfterTest: false,
				},
			},
		},
		{
			name: "exit of process with dead parent which is root",
			processes: []testProcess{
				{
					isAlive:        false,
					existAfterTest: false,
				},
				{
					isAlive:        true,
					existAfterTest: false,
				},
			},
		},
	}

	exitIds := taskIds{
		Pid:  exitEvent.HostProcessID,
		Ppid: exitEvent.HostParentProcessID,
	}

	for _, test := range straitTreeTests {
		t.Run(
			test.name, func(t *testing.T) {
				tree, err := buildLinearTree(test.processes, exitIds)
				require.NoError(t, err)

				require.NoError(t, tree.ProcessExitEvent(&exitEvent))
				proc, err := tree.getProcess(exitIds.Pid)
				require.NoError(t, err)
				assert.False(
					t,
					proc.isAlive(time.Unix(0, int64(exitEvent.Timestamp))),
					"Fork - %d, exit - %d",
					proc.getForkTime(),
					proc.getExitTime(),
				)
				// There should be a parent to the root and its parent from the fork event
				assert.Equal(t, len(test.processes)+2, tree.processes.Len())
				// Only parent of root has thread, its parent is unknown
				assert.Equal(t, len(test.processes)+1, tree.threads.Len())

				tree.emptyDeadProcessesCache()

				// There should be a parent to the root and its parent
				expectedExistingProcs := 2
				for _, testProc := range test.processes {
					if testProc.existAfterTest {
						expectedExistingProcs++
					}
				}
				// Parent of root's parent is unknown, so it has no threads
				expectedExistingThreads := expectedExistingProcs - 1

				assert.Equal(t, expectedExistingProcs, tree.processes.Len())
				assert.Equal(t, expectedExistingProcs, tree.processesGC.Len())
				assert.Equal(t, expectedExistingThreads, tree.threads.Len())
				assert.Equal(t, expectedExistingThreads, tree.threadsGC.Len())

				// Check that all nodes removed as expected
				eLivingNodes := 0
				exitProcessIndex := len(test.processes) - 1
				for i, tp := range test.processes {
					existInTree := tree.hasProcess(exitEvent.HostThreadID - (exitProcessIndex - i))
					assert.Equal(t, tp.existAfterTest, existInTree)
					if tp.isAlive && i != exitProcessIndex {
						eLivingNodes = i + 1
					}
				}
				p, err := tree.getProcess(exitEvent.HostProcessID - exitProcessIndex)
				if err == nil {
					rLivingChildren := countChildTreeNodes(p)
					assert.NotZero(t, rLivingChildren)
					assert.Equal(t, eLivingNodes, rLivingChildren)
				} else {
					assert.Zero(t, eLivingNodes)
				}
			},
		)
	}
}

// testExitWithSiblings tests exit event to a process with living siblings under the same process.
// The general behavior we expect here is that only the process will be exited and deleted.
func testExitWithSiblings(t *testing.T) {
	const exitPid = 22482
	exitEvent := getExitEvent(exitPid, exitPid, true)

	multiChildrenTests := []struct {
		name        string
		siblingsNum int
		exitIndex   int
	}{
		{
			name:        "2 siblings and first exit",
			siblingsNum: 2,
			exitIndex:   0,
		},
		{
			name:        "2 siblings and second exit",
			siblingsNum: 2,
			exitIndex:   1,
		},
		{
			name:        "3 siblings and first exit",
			siblingsNum: 3,
			exitIndex:   0,
		},
		{
			name:        "3 siblings and second exit",
			siblingsNum: 3,
			exitIndex:   1,
		},
		{
			name:        "3 siblings and third exit",
			siblingsNum: 3,
			exitIndex:   2,
		},
	}
	const ppid = 123
	for _, test := range multiChildrenTests {
		t.Run(
			test.name, func(t *testing.T) {
				tree, err := buildWideBranchTree(test.siblingsNum, test.exitIndex, ppid, exitPid)
				require.NoError(t, err)
				require.NoError(t, tree.ProcessExitEvent(&exitEvent))
				proc, err := tree.getProcess(exitPid)
				require.NoError(t, err)
				assert.False(
					t,
					proc.isAlive(time.Unix(0, int64(exitEvent.Timestamp))),
					"Fork - %d, exit - %d",
					proc.getForkTime(),
					proc.getExitTime(),
				)
				// There should be a parent to the root and its parent from the fork event
				assert.Equal(t, test.siblingsNum+3, tree.processes.Len())
				// Only parent of root has thread, its parent is unknown
				assert.Equal(t, test.siblingsNum+2, tree.threads.Len())

				tree.emptyDeadProcessesCache()

				assert.Equal(t, test.siblingsNum+2, tree.processes.Len())
				assert.Equal(t, test.siblingsNum+2, tree.processesGC.Len())
				assert.Equal(t, test.siblingsNum+1, tree.threads.Len())
				assert.Equal(t, test.siblingsNum+1, tree.threadsGC.Len())

				pp, err := tree.getProcess(ppid)
				require.NoError(t, err)
				assert.Equal(t, true, pp.isAlive(time.Unix(0, int64(exitEvent.Timestamp))))
				// Contains that all nodes removed as expected
				for i := 0; i < test.siblingsNum; i++ {
					pid := exitPid - test.exitIndex + i
					_, childExist := pp.getChild(pid)
					if i == test.exitIndex {
						assert.False(t, tree.hasProcess(pid), "process index %d", i)
						assert.False(t, childExist, "process index %d", i)
					} else {
						assert.True(t, tree.hasProcess(pid), "process index %d", i)
						assert.True(t, childExist, "process index %d", i)
					}
				}
				assert.Equal(t, test.siblingsNum, countChildTreeNodes(pp))
			},
		)
	}
}

// testThreadExit checks thread exit event, when the process doesn't die.
// This should only cause the thread to be considered dead from this point, without any deletion.
func testThreadExit(t *testing.T) {
	pid := 22482
	parentHostIds := taskIds{
		Pid:  pid - 1,
		Tid:  pid - 1,
		Ppid: 0,
	}
	parentNsIds := parentHostIds
	newProcessHostIds := taskIds{
		Pid:  pid,
		Tid:  pid,
		Ppid: 0,
	}
	newProcessNsIds := newProcessHostIds

	testCases := []struct {
		name                 string
		amountOfThreads      int
		exitedThreadsIndexes []int
	}{
		{
			name:                 "single existing thread exit",
			amountOfThreads:      1,
			exitedThreadsIndexes: []int{0},
		},
		{
			name:                 "single thread exit from multiple threads",
			amountOfThreads:      3,
			exitedThreadsIndexes: []int{1},
		},
		{
			name:                 "all threads exit",
			amountOfThreads:      3,
			exitedThreadsIndexes: []int{0, 1, 2},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				tree, err := NewProcessTree(testsTreeConfig)
				require.NoError(t, err)

				for i := 0; i < tc.amountOfThreads; i++ {
					threadHostIds := newProcessHostIds
					threadHostIds.Tid += i

					threadNsIds := newProcessNsIds
					threadNsIds.Tid += i

					processForkEvent := getForkEvent(
						parentHostIds,
						parentNsIds,
						threadHostIds,
						threadNsIds,
					)
					err = tree.ProcessForkEvent(&processForkEvent)
					require.NoError(t, err)
				}

				for _, index := range tc.exitedThreadsIndexes {
					threadExit := getExitEvent(pid, pid+index, false)
					err = tree.ProcessExitEvent(&threadExit)
					require.NoError(t, err)
				}

				proc, err := tree.getProcess(pid)
				require.NoError(t, err)
				require.Equal(t, len(proc.getThreads()), tc.amountOfThreads)
				for _, index := range tc.exitedThreadsIndexes {
					shouldBeAlive := true
					for _, exitIndex := range tc.exitedThreadsIndexes {
						if index == exitIndex {
							shouldBeAlive = false
							break
						}
					}
					thread, ok := proc.getThread(pid + index)
					require.True(t, ok)
					assert.Equal(t, shouldBeAlive, thread.isAlive(time.Unix(0, math.MaxInt)))
					assert.True(t, tree.hasThread(pid))
				}
			},
		)
	}
}

func countChildTreeNodes(p *processNode) int {
	c := 0
	for _, child := range p.getChildren() {
		c += countChildTreeNodes(child)
	}
	return 1 + c
}

// buildLinearTree create using fork events a linear tree, where the last process has the IDs
// given.
// Notice that because we use fork event, the parent will be created for the first process as well.
// Also, a slim parent of the parent will be created, without any threads or real information.
func buildLinearTree(tps []testProcess, lastProcessIDs taskIds) (*ProcessTree, error) {
	tree, err := NewProcessTree(testsTreeConfig)
	if err != nil {
		return nil, err
	}

	exitProcessIndex := len(tps) - 1

	for i := 0; i < len(tps); i++ {
		parentHostIds := taskIds{
			Pid:  lastProcessIDs.Pid - (exitProcessIndex - i) - 1,
			Tid:  lastProcessIDs.Pid - (exitProcessIndex - i) - 1,
			Ppid: lastProcessIDs.Pid - (exitProcessIndex - i) - 2,
		}
		parentNsIds := parentHostIds
		newProcessHostIds := taskIds{
			Pid:  lastProcessIDs.Pid - (exitProcessIndex - i),
			Tid:  lastProcessIDs.Pid - (exitProcessIndex - i),
			Ppid: lastProcessIDs.Pid - (exitProcessIndex - i) - 1,
		}
		newProcessNsIds := newProcessHostIds
		forkEvent := getForkEvent(newProcessHostIds, newProcessNsIds, parentHostIds, parentNsIds)
		err := tree.ProcessForkEvent(&forkEvent)
		if err != nil {
			return nil, err
		}
	}

	for i, tp := range tps {
		if !tp.isAlive {
			hostPid := lastProcessIDs.Pid - (exitProcessIndex - i)
			hostTid := hostPid
			procExitEvent := getExitEvent(hostPid, hostTid, true)
			err = tree.ProcessExitEvent(&procExitEvent)
			if err != nil {
				return nil, err
			}
		}
	}

	return tree, nil
}

// buildWideBranchTree create a tree consisting of a process with multiple children as specified.
// The building is done using fork events, so the root process here will have a normal parent,
// and its parent will have a slim parent as well (without threads and information).
func buildWideBranchTree(
	siblingsNum int,
	exitIndex int,
	ppid int,
	exitPid int,
) (*ProcessTree, error) {
	tree, err := NewProcessTree(testsTreeConfig)
	if err != nil {
		return nil, err
	}
	parentHostIds := taskIds{
		Pid:  ppid - 1,
		Tid:  ppid - 1,
		Ppid: ppid - 2,
	}
	parentNsIds := parentHostIds
	rootHostIds := taskIds{
		Pid:  ppid,
		Tid:  ppid,
		Ppid: ppid - 1,
	}
	rootNsIds := rootHostIds
	parentForkEvent := getForkEvent(rootHostIds, rootNsIds, parentHostIds, parentNsIds)
	err = tree.ProcessForkEvent(&parentForkEvent)
	if err != nil {
		return nil, err
	}

	for i := 0; i < siblingsNum; i++ {
		hostIds := taskIds{
			Pid:  exitPid - exitIndex + i,
			Tid:  exitPid - exitIndex + i,
			Ppid: rootHostIds.Pid,
		}
		nsIds := hostIds
		forkEvent := getForkEvent(hostIds, nsIds, rootHostIds, rootNsIds)
		err = tree.ProcessForkEvent(&forkEvent)
		if err != nil {
			return nil, err
		}
	}
	return tree, nil
}

func getExitEvent(pid int, tid int, isGroupExit bool) trace.Event {
	return trace.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       pid,
		HostThreadID:        tid,
		HostParentProcessID: 100,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessExit),
		EventName:           "sched_process_exit",
		ArgsNum:             1,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: isGroupExit},
		},
	}
}

func getForkEvent(
	hostIds taskIds,
	nsIds taskIds,
	parentHostIds taskIds,
	parentNsIds taskIds,
) trace.Event {
	return trace.Event{
		Timestamp:           1639044471928000000,
		ProcessID:           parentNsIds.Pid,
		ThreadID:            parentNsIds.Tid,
		ParentProcessID:     parentNsIds.Ppid,
		HostProcessID:       parentHostIds.Pid,
		HostThreadID:        parentHostIds.Tid,
		HostParentProcessID: parentHostIds.Ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "bash",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerId,
		Container:           trace.Container{ID: TestContainerId},
		EventID:             int(events.SchedProcessFork),
		EventName:           "sched_process_fork",
		ArgsNum:             8,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"},
				Value:   int32(parentHostIds.Tid),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"},
				Value:   int32(parentNsIds.Tid),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"},
				Value:   int32(parentHostIds.Pid),
			},
			{
				ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"},
				Value:   int32(parentNsIds.Pid),
			},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(hostIds.Tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(nsIds.Tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(hostIds.Pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(nsIds.Pid)},
		},
	}
}
