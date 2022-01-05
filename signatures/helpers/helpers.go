package helpers

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/process_tree"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"strings"

	"github.com/aquasecurity/tracee/pkg/external"
)

// GetTraceeArgumentByName fetches the argument in event with `Name` that matches argName
func GetTraceeArgumentByName(event external.Event, argName string) (external.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return external.Argument{}, fmt.Errorf("argument %s not found", argName)
}

// IsFileWrite returns whether or not the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

func GetProcessInfoFromTree(hostProcessID int) (types.ProcessInfo, error) {
	return process_tree.GetProcessInfo(hostProcessID)
}

func GetProcessLineageFromTree(hostProcessID int) (types.ProcessLineage, error) {
	return process_tree.GetProcessLineage(hostProcessID)
}
