package probes

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

// enableDisableAutoload enables or disables an eBPF program autoload setting
func enableDisableAutoload(module *bpf.Module, programName string, autoload bool) error {
	var err error

	if module == nil || programName == "" {
		return fmt.Errorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := module.GetProgram(programName)
	if err != nil {
		return err
	}

	return prog.SetAutoload(autoload)
}
