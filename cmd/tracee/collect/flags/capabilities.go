package flags

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/filters"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

const (
	CapsMainFlag        = "caps"
	AllowFailedDropFlag = "allow-failed-drop"
	CancelDropFlag      = "cancel-drop"
	AddReqCapsFlag      = "add"
)

func capabilitiesHelp() string {
	mainHelp := fmt.Sprintf(`Manage the capabilities and capabilities-related operations of tracee-ebpf
Normally, tracee will drop all capabilities not required to its operations.

Possible options:
  %-51s allow tracee-ebpf to run with high capabilities, in case that capabilities dropping fails
  %-51s cancel capabilities drop, so tracee will run with all given capabilities (unless missing required capabilities)
  %-51s add required capabilities, so tracee won't drop them`,
		AllowFailedDropFlag,
		CancelDropFlag,
		fmt.Sprintf("%s=<list_of_caps>", AddReqCapsFlag))

	exampleUses := map[string]string{
		"--%[1]s %[2]s":                          "Try capabilities drop, but continue run if failed",
		"--%[1]s %[3]s":                          "Don't do capabilities drop",
		"--%[1]s %[4]s=cap_syslog":               "Drop all required capabilities except for required and CAP_SYSLOG",
		"--%[1]s %[4]s!=cap_sys_ptrace":          "Drop all capabilities except CAP_SYS_PTRACE, unless required",
		"--%[1]s %[2]s --%[1]s %[4]s=cap_syslog": "Try drop all capabilities except for required and CAP_SYSLOG, but continue run if failed",
	}

	var exampleUsesString string
	for cmd, exp := range exampleUses {
		cmd = fmt.Sprintf(cmd, CapsMainFlag, AllowFailedDropFlag, CancelDropFlag, AddReqCapsFlag)
		exampleUsesString += fmt.Sprintf("  %-65s | %s\n", cmd, exp)
	}

	return fmt.Sprintf("%s\n\nExample uses:\n%s", mainHelp, exampleUsesString)
}

type CapsConfig struct {
	AllowHighCaps  bool
	CancelCapsDrop bool
	CapsToPreserve []cap.Value
}

func ParseCapsConfig(capsCfgArray []string) (CapsConfig, error) {
	if checkCommandIsHelp(capsCfgArray) {
		fmt.Print(capabilitiesHelp())
		os.Exit(0)
	}

	var cfg CapsConfig
	for _, opt := range capsCfgArray {
		optName := opt
		var operatorAndValues string
		operatorIndex := strings.IndexAny(opt, "=!<>")
		if operatorIndex > 0 {
			optName = opt[0:operatorIndex]
			operatorAndValues = opt[operatorIndex:]
		}

		switch optName {
		case AllowFailedDropFlag:
			cfg.AllowHighCaps = true
		case CancelDropFlag:
			cfg.CancelCapsDrop = true
		case AddReqCapsFlag:
			addedCapsFilter := filters.StringFilter{}
			err := addedCapsFilter.Parse(operatorAndValues)
			if err != nil {
				return cfg, err
			}
			if addedCapsFilter.FilterOut() {
				capsFilteredOut, err := capsStringSliceToValues(addedCapsFilter.NotEqual)
				if err != nil {
					return cfg, err
				}
				rcaps := capabilities.GetAllCapabilities()
				for _, c := range capsFilteredOut {
					rcaps = removeCapFromSlice(rcaps, c)
				}
				cfg.CapsToPreserve = rcaps
			} else {
				cfg.CapsToPreserve, err = capsStringSliceToValues(addedCapsFilter.Equal)
				if err != nil {
					return cfg, err
				}
			}
		default:
			return cfg, fmt.Errorf("illegal flag '--%s %s'. Run '--%[1]s help' for more info", CapsMainFlag, optName)
		}
	}
	return cfg, nil
}

func capsStringSliceToValues(slice []string) ([]cap.Value, error) {
	var caps []cap.Value
	if len(slice) > 0 {
		for _, cName := range slice {
			c, err := cap.FromName(strings.ToLower(cName))
			if err != nil {
				return nil, fmt.Errorf("invalid capability name - %s", cName)
			}
			caps = append(caps, c)
		}
	}
	return caps, nil
}

func removeCapFromSlice(slice []cap.Value, rcap cap.Value) []cap.Value {
	for i, c := range slice {
		if c == rcap {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
