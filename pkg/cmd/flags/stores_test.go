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
		// default values (no flags) - process is enabled by default
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		// valid single DNS flags
		{
			testName: "valid dns",
			flags:    []string{"dns"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid dns.max-entries",
			flags:    []string{"dns.max-entries=2048"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true, // Setting max-entries enables DNS
					MaxEntries: 2048,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		// valid single Process flags
		{
			testName: "valid process",
			flags:    []string{"process"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid process.max-processes",
			flags:    []string{"process.max-processes=100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting max-processes enables process
					MaxProcesses: 100,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid process.max-threads",
			flags:    []string{"process.max-threads=50"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting max-threads enables process
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   50,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName:      "invalid process.source=none",
			flags:         []string{"process.source=none"},
			expectedError: invalidStoresFlagError("process.source=none"),
		},
		{
			testName: "valid process.source=events",
			flags:    []string{"process.source=events"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting source enables process
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "events",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid process.source=both",
			flags:    []string{"process.source=both"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting source enables process
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "both",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid process.use-procfs",
			flags:    []string{"process.use-procfs"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting use-procfs enables process
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       true,
				},
			},
		},
		// valid multiple flags
		{
			testName: "valid multiple DNS flags",
			flags:    []string{"dns", "dns.max-entries=4096"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: 4096,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid multiple Process flags",
			flags:    []string{"process", "process.max-processes=200", "process.max-threads=100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: 200,
					MaxThreads:   100,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		{
			testName: "valid all flags",
			flags:    []string{"dns", "dns.max-entries=2048", "process", "process.max-processes=150", "process.max-threads=75", "process.source=both", "process.use-procfs"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: 2048,
				},
				Process: ProcessConfig{
					Enabled:      true,
					MaxProcesses: 150,
					MaxThreads:   75,
					Source:       "both",
					Procfs:       true,
				},
			},
		},
		{
			testName: "valid flags in different order",
			flags:    []string{"process.use-procfs", "dns.max-entries=512", "process.source=events", "process.max-threads=25"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true, // Setting max-entries enables DNS
					MaxEntries: 512,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting any process field enables process
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   25,
					Source:       "events",
					Procfs:       true,
				},
			},
		},
		// invalid flag format
		{
			testName: "invalid flag format missing equals with value",
			flags:    []string{"dnstrue"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dnstrue"),
		},
		{
			testName: "invalid dns.max-entries missing value",
			flags:    []string{"dns.max-entries"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.max-entries"),
		},
		{
			testName: "invalid dns.max-entries empty value",
			flags:    []string{"dns.max-entries="},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.max-entries="),
		},
		// invalid flag name
		{
			testName: "invalid flag name",
			flags:    []string{"invalid-flag=true"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("invalid-flag=true"),
		},
		{
			testName: "invalid flag name with typo",
			flags:    []string{"dns.enable=true"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.enable=true"),
		},
		// invalid DNS values
		{
			testName: "invalid dns.max-entries value non-numeric",
			flags:    []string{"dns.max-entries=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.max-entries=invalid"),
		},
		{
			testName: "invalid dns.max-entries value negative",
			flags:    []string{"dns.max-entries=-100"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.max-entries=-100"),
		},
		// invalid Process values
		{
			testName: "invalid process.max-processes value non-numeric",
			flags:    []string{"process.max-processes=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("process.max-processes=invalid"),
		},
		{
			testName: "invalid process.max-threads value non-numeric",
			flags:    []string{"process.max-threads=invalid"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("process.max-threads=invalid"),
		},
		// valid edge cases
		{
			testName: "invalid zero values",
			flags:    []string{"dns.max-entries=0", "process.max-processes=0", "process.max-threads=0"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    false,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("dns.max-entries=0"),
		},
		{
			testName: "valid large values",
			flags:    []string{"dns.max-entries=999999", "process.max-processes=999999", "process.max-threads=999999"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true, // Setting max-entries enables DNS
					MaxEntries: 999999,
				},
				Process: ProcessConfig{
					Enabled:      true, // Setting max-processes or max-threads enables process
					MaxProcesses: 999999,
					MaxThreads:   999999,
					Source:       "",
					Procfs:       false,
				},
			},
		},
		// mixed valid and invalid
		{
			testName: "mixed valid and invalid flag name",
			flags:    []string{"dns", "invalid-flag=value"},
			expectedReturn: StoresConfig{
				DNS: DNSConfig{
					Enabled:    true,
					MaxEntries: dns.DefaultCacheSize,
				},
				Process: ProcessConfig{
					Enabled:      true, // Enabled by default
					MaxProcesses: process.DefaultProcessCacheSize,
					MaxThreads:   process.DefaultThreadCacheSize,
					Source:       "",
					Procfs:       false,
				},
			},
			expectedError: invalidStoresFlagError("invalid-flag=value"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			stores, err := PrepareStores(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				// Error can come from either PrepareStores or parseSize, check that it contains the expected message
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn, stores)
			}
		})
	}
}
