package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

const (
	StoresFlag = "stores"

	dnsEnabled        = "dns.enabled"
	dnsMaxEntries     = "dns.max-entries"
	processEnabled    = "process.enabled"
	processMaxProcs   = "process.max-processes"
	processMaxThreads = "process.max-threads"
	processSource     = "process.source"
	processUseProcfs  = "process.use-procfs"

	storesInvalidFlag = "invalid stores flag: %s, use 'trace man stores' for more info"
)

// ProcessConfig is the config for the process tree
type ProcessConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	MaxProcesses int    `mapstructure:"max-processes"`
	MaxThreads   int    `mapstructure:"max-threads"`
	Source       string `mapstructure:"source"`
	Procfs       bool   `mapstructure:"use-procfs"`
}

// DNSConfig is the config for the DNS cache
type DNSConfig struct {
	Enabled    bool `mapstructure:"enabled"`
	MaxEntries int  `mapstructure:"max-entries"`
}

// StoresConfig is the config for the stores
type StoresConfig struct {
	DNS     DNSConfig     `mapstructure:"dns"`
	Process ProcessConfig `mapstructure:"process"`
}

// flags returns the flags for the stores config
func (s *StoresConfig) flags() []string {
	flags := []string{}

	if s.DNS.Enabled {
		flags = append(flags, dnsEnabled)
	}
	if s.DNS.MaxEntries != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", dnsMaxEntries, s.DNS.MaxEntries))
	}

	if s.Process.Enabled {
		flags = append(flags, processEnabled)
	}
	if s.Process.MaxProcesses != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", processMaxProcs, s.Process.MaxProcesses))
	}
	if s.Process.MaxThreads != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", processMaxThreads, s.Process.MaxThreads))
	}
	if s.Process.Source != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", processSource, s.Process.Source))
	}
	if s.Process.Procfs {
		flags = append(flags, processUseProcfs)
	}

	return flags
}

// GetProcTreeConfig returns the process tree config
func (s *StoresConfig) GetProcTreeConfig() process.ProcTreeConfig {
	source := process.SourceNone

	if s.Process.Enabled {
		switch s.Process.Source {
		case "events":
			source = process.SourceEvents
		case "signals":
			source = process.SourceSignals
		case "both":
			source = process.SourceBoth
		}
	}

	return process.ProcTreeConfig{
		Enabled:              s.Process.Enabled,
		Source:               source,
		ProcessCacheSize:     s.Process.MaxProcesses,
		ThreadCacheSize:      s.Process.MaxThreads,
		ProcfsInitialization: s.Process.Procfs,
		ProcfsQuerying:       s.Process.Procfs,
	}
}

// GetDNSCacheConfig returns the DNS cache config
func (s *StoresConfig) GetDNSCacheConfig() dns.Config {
	return dns.Config{
		Enable:    s.DNS.Enabled,
		CacheSize: s.DNS.MaxEntries,
	}
}

// PrepareStores prepares the stores config from the command line flags
// and returns the stores config and an error if the flags are invalid
func PrepareStores(storeSlice []string) (StoresConfig, error) {
	config := StoresConfig{
		DNS: DNSConfig{
			Enabled:    false,
			MaxEntries: dns.DefaultCacheSize,
		},
		Process: ProcessConfig{
			Enabled:      false,
			MaxProcesses: process.DefaultProcessCacheSize,
			MaxThreads:   process.DefaultThreadCacheSize,
			Source:       process.SourceNone.String(),
			Procfs:       true,
		},
	}

	for _, flag := range storeSlice {
		values := strings.SplitN(flag, "=", 2)

		flagName := values[0]

		if len(values) != 2 && !isStoresBoolFlag(flagName) {
			return config, errfmt.Errorf(storesInvalidFlag, flag)
		}

		if len(values) != 1 && isStoresBoolFlag(flagName) {
			return config, errfmt.Errorf(storesInvalidFlag, flag)
		}

		switch flagName {
		case dnsEnabled:
			config.DNS.Enabled = true
		case dnsMaxEntries:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.DNS.MaxEntries = size
		case processEnabled:
			config.Process.Enabled = true
		case processMaxProcs:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.Process.MaxProcesses = size
		case processMaxThreads:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.Process.MaxThreads = size
		case processSource:
			if values[1] == "" {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.Source = values[1]
		case processUseProcfs:
			config.Process.Procfs = true
		default:
			return config, errfmt.Errorf(storesInvalidFlag, flag)
		}
	}

	return config, nil
}

// parseSize parses a string value as a size and returns an error if the value is not a positive integer
func parseSize(value, flag string) (int, error) {
	size, err := strconv.Atoi(value)
	if err != nil || size <= 0 {
		return 0, errfmt.Errorf(storesInvalidFlag, flag)
	}
	return size, nil
}

// isStoresBoolFlag checks if a flag is a boolean flag for the stores config
func isStoresBoolFlag(flagName string) bool {
	return flagName == dnsEnabled || flagName == processEnabled || flagName == processUseProcfs
}

// invalidStoresFlagError formats the error message for an invalid stores flag.
func invalidStoresFlagError(flag string) string {
	return fmt.Sprintf(storesInvalidFlag, flag)
}
