package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

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
				processes:  map[int]*types.ProcessInfo{},
				containers: map[string]*containerProcessTree{},
			}
			exitProcessIndex := len(test.processes) - 1
			// Build the container tree
			for i, tp := range test.processes {
				np := types.ProcessInfo{
					IsAlive: tp.isAlive,
					InHostIDs: types.ProcessIDs{
						Tid:  exitEvent.HostThreadID - (exitProcessIndex - i),
						Pid:  exitEvent.HostProcessID - (exitProcessIndex - i),
						Ppid: exitEvent.HostParentProcessID - (exitProcessIndex - i),
					},
					ThreadsCount: 1,
				}
				tree.processes[np.InHostIDs.Tid] = &np
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
			tree.EmptyProcessCache()
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
