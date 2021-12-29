package process_tree

import (
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type processNode struct {
	InContainerIDs  types.ProcessIDs
	InHostIDs       types.ProcessIDs
	ContainerID     string
	ProcessName     string
	Cmd             []string
	ExecutionBinary types.BinaryInfo
	StartTime       int
	ExecTime        int
	ParentProcess   *processNode
	ChildProcesses  []*processNode
	ThreadsCount    int
	IsAlive         bool
	Status          roaring.Bitmap // Values type are ProcessInformationStatus
}

type containerProcessTree struct {
	Root *processNode
}

type ProcessTree struct {
	containers         map[string]*containerProcessTree
	processes          map[int]*processNode
	deadProcessesCache []int
}

func (tree *ProcessTree) GetProcessInfo(hostProcessID int) (*processNode, error) {
	process, ok := tree.processes[hostProcessID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return process, nil
}

// GetProcessLineage returns list of processes starting with the ID matching events back to the root of the container
// or oldest registered ancestor in the container (if root is missing)
func (tree *ProcessTree) GetProcessLineage(hostProcessID int) ([]*processNode, error) {
	process, err := tree.GetProcessInfo(hostProcessID)
	if err != nil {
		return nil, err
	}
	var lineage []*processNode
	for process != nil {
		lineage = append(lineage, process)
		process = process.ParentProcess
	}
	return lineage, nil
}
