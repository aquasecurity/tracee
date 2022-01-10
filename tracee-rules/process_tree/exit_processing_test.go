package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type testProcess struct {
	isAlive bool
	aErr    error
}

func TestProcessTree_ProcessExit(t *testing.T) {
	t.Run("Linear tree", testLinearTreeExit)
	t.Run("Exit of process with siblings", testExitWithSiblings)
}

func testLinearTreeExit(t *testing.T) {
	exitEvent := getExitEvent()

	straitTreeTests := []struct {
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

	exitIDs := types.ProcessIDs{
		Pid:  exitEvent.HostProcessID,
		Ppid: exitEvent.HostParentProcessID,
	}

	for _, test := range straitTreeTests {
		t.Run(test.name, func(t *testing.T) {
			tree, err := buildLinearTree(test.processes, exitIDs)
			require.NoError(t, err)

			require.NoError(t, tree.processExitEvent(&exitEvent))
			tree.emptyDeadProcessesCache()
			// Check that all nodes removed as expected
			eLivingNodes := 0
			exitProcessIndex := len(test.processes) - 1
			for i, tp := range test.processes {
				_, err = tree.GetProcessInfo(exitEvent.HostThreadID - (exitProcessIndex - i))
				assert.Equal(t, tp.aErr, err)
				if tp.isAlive && i != exitProcessIndex {
					eLivingNodes = i + 1
				}
			}
			p, err := tree.GetProcessInfo(exitEvent.HostProcessID - exitProcessIndex)
			if err == nil {
				rLivingChildren := countChildTreeNodes(p)
				assert.NotZero(t, rLivingChildren)
				assert.Equal(t, eLivingNodes, rLivingChildren)
			} else {
				assert.Zero(t, eLivingNodes)
			}
		})
	}
}

func testExitWithSiblings(t *testing.T) {
	exitEvent := getExitEvent()

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
	const ppid = 1
	for _, test := range multiChildrenTests {
		t.Run(test.name, func(t *testing.T) {
			tree := buildWideBranchTree(test.siblingsNum, test.exitIndex, &exitEvent, ppid)
			require.NoError(t, tree.processExitEvent(&exitEvent))
			tree.emptyDeadProcessesCache()

			pp, err := tree.GetProcessInfo(ppid)
			require.NoError(t, err)
			assert.Equal(t, true, pp.IsAlive)
			// Check that all nodes removed as expected
			for i := 0; i < test.siblingsNum; i++ {
				p, err := tree.GetProcessInfo(exitEvent.HostThreadID - test.exitIndex + i)
				if i == test.exitIndex {
					assert.Equal(t, fmt.Errorf("no process with given ID is recorded"), err)
					assert.NotContains(t, pp.ChildProcesses, p)
				} else {
					assert.NoError(t, err)
					assert.Contains(t, pp.ChildProcesses, p)
				}
			}
			assert.Equal(t, test.siblingsNum, countChildTreeNodes(pp))
		})
	}
}

func countChildTreeNodes(p *processNode) int {
	c := 0
	for _, chld := range p.ChildProcesses {
		c += countChildTreeNodes(chld)
	}
	return 1 + c
}

func buildLinearTree(tps []testProcess, lastProcessIDs types.ProcessIDs) (ProcessTree, error) {
	tree := ProcessTree{
		processes: map[int]*processNode{},
	}

	exitProcessIndex := len(tps) - 1

	for i, tp := range tps {
		np := processNode{
			IsAlive: tp.isAlive,
			InHostIDs: types.ProcessIDs{
				Pid:  lastProcessIDs.Pid - (exitProcessIndex - i),
				Ppid: lastProcessIDs.Ppid - (exitProcessIndex - i),
			},
			ThreadsExits: map[int]timestamp{
				lastProcessIDs.Pid - (exitProcessIndex - i): timestamp(0),
			},
		}
		tree.processes[np.InHostIDs.Pid] = &np
		if i != 0 {
			var err error
			np.ParentProcess, err = tree.GetProcessInfo(lastProcessIDs.Pid - (exitProcessIndex - i + 1))
			if err != nil {
				return tree, err
			}
			np.ParentProcess.ChildProcesses = append(np.ParentProcess.ChildProcesses, &np)
		}
	}

	return tree, nil
}

func buildWideBranchTree(siblingsNum int, exitIndex int, exitEvent *external.Event, ppid int) ProcessTree {
	parentProcess := &processNode{
		InHostIDs: types.ProcessIDs{
			Pid:  ppid,
			Ppid: 0,
		},
		ThreadsExits: map[int]timestamp{
			ppid: timestamp(0),
		},
		ContainerID: exitEvent.ContainerID,
		IsAlive:     true,
	}
	tree := ProcessTree{
		processes: map[int]*processNode{
			parentProcess.InHostIDs.Pid: parentProcess,
		},
	}

	for i := 0; i < siblingsNum; i++ {
		cp := &processNode{
			InHostIDs: types.ProcessIDs{
				Pid:  exitEvent.HostProcessID - exitIndex + i,
				Ppid: ppid,
			},
			ThreadsExits: map[int]timestamp{
				exitEvent.HostThreadID - exitIndex + i: timestamp(0),
			},
			ContainerID:   exitEvent.ContainerID,
			ParentProcess: parentProcess,
			IsAlive:       true,
		}
		parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, cp)
		tree.processes[cp.InHostIDs.Pid] = cp
	}
	return tree
}

func getExitEvent() external.Event {
	return external.Event{
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
			{ArgMeta: external.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: true},
		},
	}
}
