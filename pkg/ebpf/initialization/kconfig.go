package initialization

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// Custom KernelConfigOption's to extend kernel_config helper support
// Add here all kconfig variables used within tracee.bpf.c
const (
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER environment.KernelConfigOption = iota + environment.CUSTOM_OPTION_START
)

var kconfigUsed = map[environment.KernelConfigOption]string{
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER: "CONFIG_ARCH_HAS_SYSCALL_WRAPPER",
}

// LoadKconfigValues load all kconfig variables used within tracee.bpf.c
func LoadKconfigValues(kc *environment.KernelConfig) (map[environment.KernelConfigOption]environment.KernelConfigOptionValue, error) {
	values := make(map[environment.KernelConfigOption]environment.KernelConfigOptionValue)
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
			values[key] = environment.UNDEFINED
		}
		values[CONFIG_ARCH_HAS_SYSCALL_WRAPPER] = environment.BUILTIN // assume CONFIG_ARCH_HAS_SYSCALL_WRAPPER is a BUILTIN option
	} else {
		for key := range kconfigUsed {
			values[key] = kc.GetValue(key) // undefined, builtin OR module
		}
	}
	return values, nil
}
