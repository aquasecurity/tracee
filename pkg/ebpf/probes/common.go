package probes

import (
	"errors"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/errfmt"
)

// enableDisableAutoload enables or disables an eBPF program automatic attachment to/from its hook.
func enableDisableAutoload(module *bpf.Module, programName string, autoload bool) error {
	var err error

	if module == nil || programName == "" {
		return errfmt.Errorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := module.GetProgram(programName)
	if err != nil {
		// Program not found (ENOENT) is expected for probes that don't exist in this kernel version
		// or for optional probes that may not be compiled into the BPF object.
		// This is not an error - just means the probe can't be used.
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return errfmt.WrapError(err)
	}

	err = prog.SetAutoload(autoload)
	if err != nil {
		// EINVAL means the BPF object is already loaded and autoload cannot be changed.
		// This is expected when probes are being removed/disabled after loading.
		// We can safely ignore this since the program state is already determined.
		if errors.Is(err, syscall.EINVAL) {
			return nil
		}
		return err
	}

	return nil
}
