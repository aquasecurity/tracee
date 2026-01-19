package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	DetectorsFlag = "detectors"

	invalidDetectorsFlagError = "invalid detectors flag: '%s', use 'tracee man detectors' for more info"
)

// DetectorsConfig is the configuration for detectors
type DetectorsConfig struct {
	Paths []string `mapstructure:",remain"`
}

// flags returns the flags for the detectors config
func (c *DetectorsConfig) flags() []string {
	return c.Paths
}

// PrepareDetectors prepares the detectors configuration from a list of flags
func PrepareDetectors(flags []string) (DetectorsConfig, error) {
	config := DetectorsConfig{
		Paths: make([]string, 0),
	}

	for _, flag := range flags {
		if flag == "" || strings.Contains(flag, "=") {
			return DetectorsConfig{}, errfmt.Errorf(invalidDetectorsFlagError, flag)
		}

		config.Paths = append(config.Paths, flag)
	}

	return config, nil
}

// invalidDetectorsFlagErrorMsg formats the error message for an invalid detectors flag
func invalidDetectorsFlagErrorMsg(flag string) string {
	return fmt.Sprintf(invalidDetectorsFlagError, flag)
}
