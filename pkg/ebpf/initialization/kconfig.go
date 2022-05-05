package initialization

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"os"
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
func LoadKconfigValues(kc *helpers.KernelConfig, isDebug bool) (map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue, error) {
	values := make(map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue)
	var err error
	for key, keyString := range kconfigUsed {
		if err = kc.AddCustomKernelConfig(key, keyString); err != nil {
			return nil, err
		}
	}

	// re-load kconfig and get just added kconfig option values
	if err = kc.LoadKernelConfig(); err != nil { // invalid kconfig file: assume values then
		if isDebug {
			fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
		}
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
