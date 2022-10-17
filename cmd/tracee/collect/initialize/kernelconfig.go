package initialize

import (
	"fmt"
	"os"

	"github.com/aquasecurity/libbpfgo/helpers"
)

func KernelConfig() (*helpers.KernelConfig, error) {
	kernelConfig, err := helpers.InitKernelConfig()
	if err != nil {
		// do not fail if we cannot init kconfig - print out warning messages
		fmt.Fprintf(os.Stderr, "KConfig: warning: could not check enabled kconfig features\n(%v)\n", err)
		fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
		return kernelConfig, nil
	}

	kernelConfig.AddNeeded(helpers.CONFIG_BPF, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_BPF_SYSCALL, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_KPROBE_EVENTS, helpers.BUILTIN)
	kernelConfig.AddNeeded(helpers.CONFIG_BPF_EVENTS, helpers.BUILTIN)
	missing := kernelConfig.CheckMissing() // do fail if we found os-release file and it is not enough
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing kernel configuration options: %s", missing)
	}
	return kernelConfig, nil
}
