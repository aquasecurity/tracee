package initialize

import (
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

func KernelConfig() (*environment.KernelConfig, error) {
	kernelConfig, err := environment.InitKernelConfig()
	if err != nil {
		// do not fail if we cannot init kconfig - print out warning messages
		logger.Warnw("KConfig: could not check enabled kconfig features", "error", err)
		logger.Warnw("KConfig: assuming kconfig values, might have unexpected behavior")
		return kernelConfig, nil
	}

	kernelConfig.AddNeeded(environment.CONFIG_BPF, environment.BUILTIN)
	kernelConfig.AddNeeded(environment.CONFIG_BPF_SYSCALL, environment.BUILTIN)
	kernelConfig.AddNeeded(environment.CONFIG_KPROBE_EVENTS, environment.BUILTIN)
	kernelConfig.AddNeeded(environment.CONFIG_UPROBE_EVENTS, environment.BUILTIN)
	kernelConfig.AddNeeded(environment.CONFIG_BPF_EVENTS, environment.BUILTIN)
	for _, missingOpt := range kernelConfig.CheckMissing() {
		// do not fail if there are missing options, let it fail later by trying
		logger.Warnw("KConfig: could not detect kconfig option", "option", missingOpt)
	}

	return kernelConfig, nil
}
