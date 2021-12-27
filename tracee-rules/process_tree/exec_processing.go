package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// processExecEvent fill the fields of the process according to exec information.
// It also fills the missing information from the fork.
func (tree *ProcessTree) processExecEvent(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
	}
	if process.ParentProcess == nil {
		tree.generateParentProcess(process)
	}
	if process.Status.Contains(uint32(types.HollowParent)) {
		fillHollowParentProcessGeneralEvent(process, event)
	}
	process.ExecutionBinary, process.Cmd, err = parseExecArguments(event)
	if err != nil {
		return err
	}
	process.ProcessName = event.ProcessName
	process.ExecTime = event.Timestamp

	process.Status.Add(uint32(types.Executed))
	return nil
}

func parseExecArguments(event external.Event) (types.BinaryInfo, []string, error) {
	var binaryInfo types.BinaryInfo
	var cmd []string
	execArgv, err := getArgumentByName(event, "argv")
	if err != nil {
		return binaryInfo, cmd, err
	}
	var ok bool
	cmd, ok = execArgv.Value.([]string)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execArgv.Name,
			execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return binaryInfo, cmd, err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execPathName.Name,
			execPathName.Type)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return binaryInfo, cmd, err
	}
	ctime64, ok := execCtime.Value.(uint64)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
			execCtime.Name,
			execCtime.Type)
	}
	hash := ""
	execHash, err := getArgumentByName(event, "sha256")
	// Executed binary hash is not mandatory field, so failing in reading it does not mean error necessarily
	if err == nil {
		hash, ok = execHash.Value.(string)
		if !ok {
			return binaryInfo, cmd, fmt.Errorf("invalid type of argument '%s' - %T",
				execPathName.Name,
				execPathName.Type)
		}
	}

	binaryInfo = types.BinaryInfo{
		Path:  pathName,
		Hash:  hash,
		Ctime: uint(ctime64),
	}
	return binaryInfo, cmd, nil
}
