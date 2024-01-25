package probes

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
)

// enableDisableAutoload enables or disables an eBPF program automatic attachment to/from its hook.
func enableDisableAutoload(programName string, autoload bool) error {
	var err error

	if programName == "" {
		return errfmt.Errorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := extensions.Modules.Get("core").GetProgram(programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return prog.SetAutoload(autoload)
}
