package flags

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

const (
	storesInvalidFlag = "invalid stores flag: %s, use 'trace man stores' for more info"
)

func storesHelp() string {
	return `Select different options for the data stores.

Example:
  --stores dns.enabled=<true/false>
  --stores dns.size=<size>
  --stores process.enabled=<true/false>
  --stores process.processes=<num_processes>
  --stores process.threads=<num_threads>
  --stores process.source=
  --stores process.use-procfs=<true/false>
}

Use the flag multiple times to choose multiple options:
  --stores dns.enabled=A --stores dns.size=B
`
}

// StoresConfig is the config for the stores
type StoresConfig struct {
	DNS     dns.Config
	Process process.ProcTreeConfig
}

// PrepareStores prepares the stores config from the command line flags
// and returns the stores config and an error if the flags are invalid
func PrepareStores(storeSlice []string) (StoresConfig, error) {
	config := StoresConfig{
		DNS: dns.Config{
			Enable:    false, // disabled by default
			CacheSize: dns.DefaultCacheSize,
		},
		Process: process.ProcTreeConfig{
			Source:               process.SourceNone, // disabled by default
			ProcessCacheSize:     process.DefaultProcessCacheSize,
			ThreadCacheSize:      process.DefaultThreadCacheSize,
			ProcfsInitialization: true,
			ProcfsQuerying:       true,
		},
	}

	for _, flag := range storeSlice {
		values := strings.Split(flag, "=")
		if len(values) != 2 || values[0] == "" || values[1] == "" {
			return config, errfmt.Errorf(storesInvalidFlag, flag)
		}
		switch values[0] {
		case "dns.enabled":
			switch values[1] {
			case "true", "false":
			default:
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.DNS.Enable = values[1] == "true"
		case "dns.size":
			size, err := strconv.Atoi(values[1])
			if err != nil {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			if size <= 0 {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.DNS.CacheSize = size
		case "process.enabled":
			switch values[1] {
			case "true", "false":
			default:
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.Enabled = values[1] == "true"
		case "process.processes":
			size, err := strconv.Atoi(values[1])
			if err != nil {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			if size <= 0 {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.ProcessCacheSize = size
		case "process.threads":
			size, err := strconv.Atoi(values[1])
			if err != nil {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			if size <= 0 {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.ThreadCacheSize = size
		case "process.source":
			switch values[1] {
			case "none":
				config.Process.Source = process.SourceNone
			case "events":
				config.Process.Source = process.SourceEvents
			case "signals":
				config.Process.Source = process.SourceSignals
			case "both":
				config.Process.Source = process.SourceBoth
			default:
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
		case "process.use-procfs":
			switch values[1] {
			case "true", "false":
			default:
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.ProcfsInitialization = values[1] == "true"
			config.Process.ProcfsQuerying = values[1] == "true"
		default:
			return config, errfmt.Errorf(storesInvalidFlag, flag)
		}
	}

	return config, nil
}
