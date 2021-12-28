package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type containerProcessTree struct {
	Root *types.ProcessInfo
}

type ProcessTree struct {
	containers         map[string]*containerProcessTree
	processes          map[int]*types.ProcessInfo
	deadProcessesCache []int
}

func (tree *ProcessTree) GetProcessInfo(hostProcessID int) (*types.ProcessInfo, error) {
	process, ok := tree.processes[hostProcessID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return process, nil
}

// GetProcessLineage returns list of processes starting with the ID matching events back to the root of the container
// or oldest registered ancestor in the container (if root is missing)
func (tree *ProcessTree) GetProcessLineage(hostProcessID int) (types.ProcessLineage, error) {
	process, err := tree.GetProcessInfo(hostProcessID)
	if err != nil {
		return nil, err
	}
	var lineage types.ProcessLineage
	for process != nil {
		lineage = append(lineage, *process)
		process = process.ParentProcess
	}
	return lineage, nil
}
