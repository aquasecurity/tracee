package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	DetectorsFlag = "detectors"

	// yamlDirFlag is the CLI flag name for YAML detector directories (--detectors yaml-dir=/path)
	yamlDirFlag = "yaml-dir"

	// YAMLDirFlag is the config file key for YAML detector directories (detectors.yaml-dir)
	YAMLDirFlag = "detectors.yaml-dir"

	invalidDetectorsFlagError = "invalid detectors flag: '%s', use 'tracee man detectors' for more info"
)

// DetectorsConfig is the configuration for detectors
type DetectorsConfig struct {
	YAMLDirs []string `mapstructure:"yaml-dir"`
}

// flags returns the flags for the detectors config
func (c *DetectorsConfig) flags() []string {
	flags := make([]string, 0, len(c.YAMLDirs))

	for _, dir := range c.YAMLDirs {
		flags = append(flags, fmt.Sprintf("%s=%s", yamlDirFlag, dir))
	}

	return flags
}

// PrepareDetectors prepares the detectors configuration from a list of flags
func PrepareDetectors(flags []string) (DetectorsConfig, error) {
	config := DetectorsConfig{
		YAMLDirs: make([]string, 0),
	}

	for _, flag := range flags {
		parts := strings.Split(flag, "=")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return DetectorsConfig{}, errfmt.Errorf(invalidDetectorsFlagError, flag)
		}

		flagName := parts[0]
		flagValue := parts[1]

		switch flagName {
		case yamlDirFlag:
			config.YAMLDirs = append(config.YAMLDirs, flagValue)
		default:
			return DetectorsConfig{}, errfmt.Errorf(invalidDetectorsFlagError, flagName)
		}
	}

	return config, nil
}

// invalidDetectorsFlagErrorMsg formats the error message for an invalid detectors flag
func invalidDetectorsFlagErrorMsg(flag string) string {
	return fmt.Sprintf(invalidDetectorsFlagError, flag)
}
