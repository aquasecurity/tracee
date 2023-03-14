package initialize

import (
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func KernelConfig() (*helpers.KernelConfig, error) {
	kernelConfig, err := helpers.InitKernelConfig()
	if err != nil {
		// do not fail if we cannot init kconfig - print out warning messages
		logger.Warnw("KConfig: could not check enabled kconfig features", "error", err)
		logger.Warnw("KConfig: assuming kconfig values, might have unexpected behavior")
		return kernelConfig, nil
	}

	kernelConfig.AddNeeded(helpers.CONFIG_BPF, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_BPF_SYSCALL, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_KPROBE_EVENTS, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_BPF_EVENTS, helpers.BUILTIN)
	missing := kernelConfig.CheckMissing() // do fail if we found os-release file and it is not enough
	if len(missing) > 0 {
		return nil, errfmt.Errorf("missing kernel configuration options: %s", missing)
	}
	return kernelConfig, nil
}
