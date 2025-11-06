package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	WorkdirFlag        = "workdir"
	WorkdirDefault     = "/tmp/tracee"
	generalInvalidFlag = "invalid general flag: %s, use 'trace man general' for more info"
)

func generalHelp() string {
	return `Control general configurations.
Possible options:
[workdir=/tmp/tracee]\t\tControl general configurations
`
}

type GeneralConfig struct {
	Workdir string
}

func PrepareGeneral(generalSlice []string) (GeneralConfig, error) {
	generalConfig := GeneralConfig{
		Workdir: WorkdirDefault,
	}
	for _, flag := range generalSlice {
		parts := strings.SplitN(flag, "=", 2)

		if len(parts) != 2 {
			return generalConfig, errfmt.Errorf(generalInvalidFlag, flag)
		}

		flagName := parts[0]
		flagValue := parts[1]

		switch flagName {
		case WorkdirFlag:
			workdir := strings.TrimSpace(flagValue)
			if workdir == "" {
				return generalConfig, errfmt.Errorf("invalid general flag: %s value can't be empty, use 'trace man general' for more info", flagName)
			}

			generalConfig.Workdir = workdir

		default:
			return generalConfig, errfmt.Errorf(generalInvalidFlag, flag)
		}
	}

	return generalConfig, nil
}
