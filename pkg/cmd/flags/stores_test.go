package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

func TestPrepareStores(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn StoresConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		// valid single DNS flags
		{
			testName: "valid dns.enabled=true",
			flags:    []string{"dns.enabled=true"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    true,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid dns.enabled=false",
			flags:    []string{"dns.enabled=false"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid dns.size",
			flags:    []string{"dns.size=2048"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: 2048,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		// valid single Process flags
		{
			testName: "valid process.enabled=true",
			flags:    []string{"process.enabled=true"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              true,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.enabled=false",
			flags:    []string{"process.enabled=false"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.processes",
			flags:    []string{"process.processes=100"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     100,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.threads",
			flags:    []string{"process.threads=50"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      50,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.source=none",
			flags:    []string{"process.source=none"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.source=events",
			flags:    []string{"process.source=events"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceEvents,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.source=signals",
			flags:    []string{"process.source=signals"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceSignals,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.source=both",
			flags:    []string{"process.source=both"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceBoth,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.use-procfs=true",
			flags:    []string{"process.use-procfs=true"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid process.use-procfs=false",
			flags:    []string{"process.use-procfs=false"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: false,
					ProcfsQuerying:       false,
				},
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple DNS flags",
			flags:    []string{"dns.enabled=true", "dns.size=4096"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    true,
					CacheSize: 4096,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid multiple Process flags",
			flags:    []string{"process.enabled=true", "process.processes=200", "process.threads=100"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              true,
					ProcessCacheSize:     200,
					ThreadCacheSize:      100,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"dns.enabled=true", "dns.size=2048", "process.enabled=true", "process.processes=150", "process.threads=75", "process.source=both", "process.use-procfs=true"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    true,
					CacheSize: 2048,
				},
				Process: process.ProcTreeConfig{
					Enabled:              true,
					ProcessCacheSize:     150,
					ThreadCacheSize:      75,
					Source:               process.SourceBoth,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"process.use-procfs=true", "dns.size=512", "process.source=events", "dns.enabled=false", "process.threads=25"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: 512,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      25,
					Source:               process.SourceEvents,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		// valid duplicate flags (last one wins)
		{
			testName: "valid duplicate flags",
			flags:    []string{"dns.enabled=true", "dns.enabled=false"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: dns.DefaultCacheSize,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     process.DefaultProcessCacheSize,
					ThreadCacheSize:      process.DefaultThreadCacheSize,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		// invalid flag format (missing =)
		{
			testName:       "invalid flag format missing equals",
			flags:          []string{"dns.enabled"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enabled, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid flag format missing equals with value",
			flags:          []string{"dns.enabledtrue"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enabledtrue, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid flag format empty value",
			flags:          []string{"dns.enabled="},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enabled=, use 'trace man stores' for more info",
		},
		// invalid flag name
		{
			testName:       "invalid flag name",
			flags:          []string{"invalid-flag=true"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: invalid-flag=true, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid flag name with typo",
			flags:          []string{"dns.enable=true"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enable=true, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid flag name empty",
			flags:          []string{"=true"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: =true, use 'trace man stores' for more info",
		},
		// invalid DNS values
		{
			testName:       "invalid dns.enabled value",
			flags:          []string{"dns.enabled=yes"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enabled=yes, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid dns.size value non-numeric",
			flags:          []string{"dns.size=invalid"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.size=invalid, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid dns.size value negative",
			flags:          []string{"dns.size=-100"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.size=-100, use 'trace man stores' for more info",
		},
		// invalid Process values
		{
			testName:       "invalid process.enabled value",
			flags:          []string{"process.enabled=yes"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.enabled=yes, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid process.processes value non-numeric",
			flags:          []string{"process.processes=invalid"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.processes=invalid, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid process.threads value non-numeric",
			flags:          []string{"process.threads=invalid"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.threads=invalid, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid process.source value",
			flags:          []string{"process.source=invalid"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.source=invalid, use 'trace man stores' for more info",
		},
		{
			testName:       "invalid process.use-procfs value",
			flags:          []string{"process.use-procfs=yes"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.use-procfs=yes, use 'trace man stores' for more info",
		},
		// valid edge cases
		{ // TODO does this make sense?
			testName:       "valid zero values",
			flags:          []string{"dns.size=0", "process.processes=0", "process.threads=0"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.size=0, use 'trace man stores' for more info",
		},
		{
			testName: "valid large values",
			flags:    []string{"dns.size=999999", "process.processes=999999", "process.threads=999999"},
			expectedReturn: StoresConfig{
				DNS: dns.Config{
					Enable:    false,
					CacheSize: 999999,
				},
				Process: process.ProcTreeConfig{
					Enabled:              false,
					ProcessCacheSize:     999999,
					ThreadCacheSize:      999999,
					Source:               process.SourceNone,
					ProcfsInitialization: true,
					ProcfsQuerying:       true,
				},
			},
		},
		// mixed valid and invalid
		{
			testName:       "mixed valid and invalid flag name",
			flags:          []string{"dns.enabled=true", "invalid-flag=value"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: invalid-flag=value, use 'trace man stores' for more info",
		},
		{
			testName:       "mixed valid and invalid format",
			flags:          []string{"dns.enabled=true", "process.enabled"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: process.enabled, use 'trace man stores' for more info",
		},
		{
			testName:       "mixed valid and invalid value",
			flags:          []string{"dns.enabled=true", "dns.enabled=yes"},
			expectedReturn: StoresConfig{},
			expectedError:  "flags.PrepareStores: invalid stores flag: dns.enabled=yes, use 'trace man stores' for more info",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			stores, err := PrepareStores(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.DNS.Enable, stores.DNS.Enable)
				assert.Equal(t, tc.expectedReturn.DNS.CacheSize, stores.DNS.CacheSize)
				assert.Equal(t, tc.expectedReturn.Process.Enabled, stores.Process.Enabled)
				assert.Equal(t, tc.expectedReturn.Process.ProcessCacheSize, stores.Process.ProcessCacheSize)
				assert.Equal(t, tc.expectedReturn.Process.ThreadCacheSize, stores.Process.ThreadCacheSize)
				assert.Equal(t, tc.expectedReturn.Process.Source, stores.Process.Source)
				assert.Equal(t, tc.expectedReturn.Process.ProcfsInitialization, stores.Process.ProcfsInitialization)
				assert.Equal(t, tc.expectedReturn.Process.ProcfsQuerying, stores.Process.ProcfsQuerying)
			}
		})
	}
}
