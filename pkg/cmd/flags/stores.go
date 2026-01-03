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

	dnsFlag           = "dns"
	dnsMaxEntries     = "dns.max-entries"
	processFlag       = "process"
	processMaxProcs   = "process.max-processes"
	processMaxThreads = "process.max-threads"
	processSource     = "process.source"
	processUseProcfs  = "process.use-procfs"

	processSourceEvents  = "events"
	processSourceSignals = "signals"
	processSourceBoth    = "both"

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

	// DNS: if Enabled is true OR MaxEntries is set, add dns flag
	if s.DNS.Enabled || s.DNS.MaxEntries != 0 {
		flags = append(flags, dnsFlag)
	}
	if s.DNS.MaxEntries != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", dnsMaxEntries, s.DNS.MaxEntries))
	}

	// Process: if Enabled is true OR any Process field is set, add process flag
	// Note: Source is deprecated and ignored, so we don't include it in the output
	if s.Process.Enabled || s.Process.MaxProcesses != 0 || s.Process.MaxThreads != 0 || s.Process.Procfs {
		flags = append(flags, processFlag)
	}
	if s.Process.MaxProcesses != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", processMaxProcs, s.Process.MaxProcesses))
	}
	if s.Process.MaxThreads != 0 {
		flags = append(flags, fmt.Sprintf("%s=%d", processMaxThreads, s.Process.MaxThreads))
	}
	if s.Process.Procfs {
		flags = append(flags, processUseProcfs)
	}

	return flags
}

// GetProcessStoreConfig returns the process store config
func (s *StoresConfig) GetProcessStoreConfig() process.ProcTreeConfig {
	// Always use SourceBoth when process store is enabled.
	//
	// Why both sources?
	// - Events (pipeline): Provide synchronous, immediate updates to the process tree.
	//   These are captured directly from the eBPF program and processed in the main
	//   events pipeline, ensuring timely population before detector processing.
	//
	// - Signals (control plane): Provide asynchronous enrichment with additional
	//   context that may not be available in the fast path. The control plane can
	//   perform more expensive operations without blocking the main pipeline.
	//
	// Using only signals can create race conditions where detectors query the process
	// tree before signals populate it. Using only events risks data loss if critical
	// exec/fork/exit events are dropped. Both sources together provide the best
	// reliability and completeness.
	source := process.SourceNone
	if s.Process.Enabled {
		source = process.SourceBoth
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

// GetDNSStoreConfig returns the DNS store config
func (s *StoresConfig) GetDNSStoreConfig() dns.Config {
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
			Source:       "", // Deprecated field, kept only for backward compatibility with old configs
			Procfs:       false,
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
		case dnsFlag:
			config.DNS.Enabled = true
		case dnsMaxEntries:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.DNS.MaxEntries = size
			config.DNS.Enabled = true // Setting max-entries enables DNS
		case processFlag:
			config.Process.Enabled = true
		case processMaxProcs:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.Process.MaxProcesses = size
			config.Process.Enabled = true // Setting max-processes enables process
		case processMaxThreads:
			size, err := parseSize(values[1], flag)
			if err != nil {
				return config, err
			}
			config.Process.MaxThreads = size
			config.Process.Enabled = true // Setting max-threads enables process
		case processSource:
			if values[1] == "" {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			// Validate that source is one of the supported values
			if values[1] != processSourceSignals && values[1] != processSourceEvents && values[1] != processSourceBoth {
				return config, errfmt.Errorf(storesInvalidFlag, flag)
			}
			config.Process.Source = values[1]
			config.Process.Enabled = true // Setting source enables process
		case processUseProcfs:
			config.Process.Procfs = true
			config.Process.Enabled = true // Setting use-procfs enables process
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
	return flagName == dnsFlag || flagName == processFlag || flagName == processUseProcfs
}

// invalidStoresFlagError formats the error message for an invalid stores flag.
func invalidStoresFlagError(flag string) string {
	return fmt.Sprintf(storesInvalidFlag, flag)
}
