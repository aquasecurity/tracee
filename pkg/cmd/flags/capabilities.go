package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func capabilitiesHelp() string {
	availCaps := strings.Join(capabilities.ListAvailCaps(), "\n  ")

	return `
Opt out from dropping capabilities by default OR set specific ones.

Possible options:
  --capabilities bypass=[true|false]        | keep all capabilities during execution time.
  --capabilities add=cap_kill,cap_syslog    | add specific capabilities to the "required" capabilities ring.
  --capabilities drop=cap_chown             | drop specific capabilities from the "required" capabilities ring.

Available capabilities:
` + "  " + availCaps + "\n"
}

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
