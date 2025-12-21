package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/config"
)

const (
	CapabilitiesFlag = "capabilities"
)

// CapabilitiesConfig is the configuration for the capabilities.
type CapabilitiesConfig struct {
	Bypass bool     `mapstructure:"bypass"`
	Add    []string `mapstructure:"add"`
	Drop   []string `mapstructure:"drop"`
}

// flags returns the flags for the capabilities configuration.
func (c *CapabilitiesConfig) flags() []string {
	flags := make([]string, 0)

	flags = append(flags, fmt.Sprintf("bypass=%v", c.Bypass))
	for _, cap := range c.Add {
		flags = append(flags, fmt.Sprintf("add=%s", cap))
	}
	for _, cap := range c.Drop {
		flags = append(flags, fmt.Sprintf("drop=%s", cap))
	}

	return flags
}

// PrepareCapabilities prepares the capabilities configuration from a slice of strings.
func PrepareCapabilities(capsSlice []string) (config.CapabilitiesConfig, error) {
	capsConfig := config.CapabilitiesConfig{
		BypassCaps: false, // do not bypass capabilities by default
	}

	for _, slice := range capsSlice {
		if strings.Contains(slice, "bypass=") {
			b := strings.TrimPrefix(slice, "bypass=")
			if b == "1" || b == "true" {
				capsConfig.BypassCaps = true
			} else if b != "0" && b != "false" {
				return capsConfig, errfmt.Errorf("bypass should either be true or false")
			}
		}
		if strings.HasPrefix(slice, "add=") {
			suffix := strings.TrimPrefix(slice, "add=")
			if len(suffix) > 0 {
				slicearray := strings.Split(suffix, ",")
				for _, s := range slicearray {
					if len(s) > 0 {
						capsConfig.AddCaps = append(capsConfig.AddCaps, s)
					}
				}
			}
		}
		if strings.HasPrefix(slice, "drop=") {
			suffix := strings.TrimPrefix(slice, "drop=")
			if len(suffix) > 0 {
				slicearray := strings.Split(suffix, ",")
				for _, s := range slicearray {
					if len(s) > 0 {
						capsConfig.DropCaps = append(capsConfig.DropCaps, s)
					}
				}
			}
		}
	}

	for _, a := range capsConfig.AddCaps {
		for _, d := range capsConfig.DropCaps {
			if a == d {
				return capsConfig, errfmt.Errorf("cant add and drop %v at the same time", a)
			}
		}
	}

	return capsConfig, nil
}
