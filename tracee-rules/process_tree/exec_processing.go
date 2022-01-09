package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// processExecEvent fills process information as any other general event, but add execution information.
func (tree *ProcessTree) processExecEvent(event external.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	process.ExecutionBinary, process.Cmd, err = parseExecArguments(event)
	if err != nil {
		return err
	}
	process.ProcessName = event.ProcessName
	process.ExecTime = timestamp(event.Timestamp)

	process.Status.Add(uint32(types.Executed))
	return nil
}

const typeErrorMessage = "invalid type of argument '%s' - %T"

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
		return binaryInfo, cmd, fmt.Errorf(typeErrorMessage,
			execArgv.Name,
			execArgv.Name)
	}
	execPathName, err := getArgumentByName(event, "pathname")
	if err != nil {
		return binaryInfo, cmd, err
	}
	pathName, ok := execPathName.Value.(string)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf(typeErrorMessage,
			execPathName.Name,
			execPathName.Type)
	}
	execCtime, err := getArgumentByName(event, "ctime")
	if err != nil {
		return binaryInfo, cmd, err
	}
	ctime64, ok := execCtime.Value.(uint64)
	if !ok {
		return binaryInfo, cmd, fmt.Errorf(typeErrorMessage,
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
