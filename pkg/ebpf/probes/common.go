package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// enableDisableAutoload enables or disables an eBPF program autoload setting
func enableDisableAutoload(module *bpf.Module, programName string, autoload bool) error {
	var err error

	if module == nil || programName == "" {
		return logger.NewErrorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := module.GetProgram(programName)
	if err != nil {
		return logger.ErrorFunc(err)
	}

	return prog.SetAutoload(autoload)
}
