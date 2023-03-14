package initialization

import (
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// Custom KernelConfigOption's to extend kernel_config helper support
// Add here all kconfig variables used within tracee.bpf.c
const (
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER helpers.KernelConfigOption = iota + helpers.CUSTOM_OPTION_START
)

var kconfigUsed = map[helpers.KernelConfigOption]string{
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER: "CONFIG_ARCH_HAS_SYSCALL_WRAPPER",
}

// LoadKconfigValues load all kconfig variables used within tracee.bpf.c
func LoadKconfigValues(kc *helpers.KernelConfig) (map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue, error) {
	values := make(map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue)
	var err error
	for key, keyString := range kconfigUsed {
		if err = kc.AddCustomKernelConfig(key, keyString); err != nil {
			return nil, errfmt.WrapError(err)
		}
	}

	// re-load kconfig and get just added kconfig option values
	if err = kc.LoadKernelConfig(); err != nil { // invalid kconfig file: assume values then
		logger.Debugw("KConfig: warning: assuming kconfig values, might have unexpected behavior")
		for key := range kconfigUsed {
			values[key] = helpers.UNDEFINED
		}
		values[CONFIG_ARCH_HAS_SYSCALL_WRAPPER] = helpers.BUILTIN // assume CONFIG_ARCH_HAS_SYSCALL_WRAPPER is a BUILTIN option
	} else {
		for key := range kconfigUsed {
			values[key] = kc.GetValue(key) // undefined, builtin OR module
		}
	}
	return values, nil
}
