package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	RuntimeFlag    = "runtime"
	WorkdirDefault = "/tmp/tracee"

	workdirFlag                = "workdir"
	runtimeInvalidFlag         = "invalid runtime flag: %s, use 'trace man runtime' for more info"
	runtimeInvalidFlagEmptyVal = "invalid runtime flag: %s value can't be empty, use 'trace man runtime' for more info"
)

// RuntimeConfig represents the configuration for the runtime.
type RuntimeConfig struct {
	Workdir string `mapstructure:"workdir"`
}

// flags returns the flags for the runtime configuration.
func (c *RuntimeConfig) flags() []string {
	return []string{fmt.Sprintf("workdir=%s", c.Workdir)}
}

// PrepareRuntime prepares the runtime configuration from the command line flags.
func PrepareRuntime(runtimeSlice []string) (RuntimeConfig, error) {
	runtimeConfig := RuntimeConfig{
		Workdir: WorkdirDefault,
	}
	for _, flag := range runtimeSlice {
		parts := strings.SplitN(flag, "=", 2)

		if len(parts) != 2 {
			return runtimeConfig, errfmt.Errorf(runtimeInvalidFlag, flag)
		}

		flagName := parts[0]
		flagValue := parts[1]

		switch flagName {
		case workdirFlag:
			workdir := strings.TrimSpace(flagValue)
			if workdir == "" {
				return runtimeConfig, errfmt.Errorf(runtimeInvalidFlagEmptyVal, flagName)
			}

			runtimeConfig.Workdir = workdir

		default:
			return runtimeConfig, errfmt.Errorf(runtimeInvalidFlag, flag)
		}
	}

	return runtimeConfig, nil
}

// invalidRuntimeFlagError formats the error message for an invalid runtime flag.
func invalidRuntimeFlagError(flag string) string {
	return fmt.Sprintf(runtimeInvalidFlag, flag)
}

// invalidRuntimeFlagEmptyValueError formats the error message for an invalid runtime flag with empty value.
func invalidRuntimeFlagEmptyValueError(flagName string) string {
	return fmt.Sprintf(runtimeInvalidFlagEmptyVal, flagName)
}
