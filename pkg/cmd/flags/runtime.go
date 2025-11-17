package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	RuntimeFlag        = "runtime"
	WorkdirFlag        = "workdir"
	WorkdirDefault     = "/tmp/tracee"
	runtimeInvalidFlag = "invalid runtime flag: %s, use 'trace man runtime' for more info"
)

// TODO: remove this once we merged tracee-ebpf/tracee-rules removal pr,
// we will simpliy configs, or move configs here instead of cobra/config.go
// so flags have their config on the same file that it parses it.
type RuntimeConfig struct {
	Workdir string
}

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
		case WorkdirFlag:
			workdir := strings.TrimSpace(flagValue)
			if workdir == "" {
				return runtimeConfig, errfmt.Errorf("invalid runtime flag: %s value can't be empty, use 'trace man runtime' for more info", flagName)
			}

			runtimeConfig.Workdir = workdir

		default:
			return runtimeConfig, errfmt.Errorf(runtimeInvalidFlag, flag)
		}
	}

	return runtimeConfig, nil
}
