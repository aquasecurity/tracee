package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/config"
)

func TestCapabilitiesConfigFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   CapabilitiesConfig
		expected []string
	}{
		{
			name: "empty config",
			config: CapabilitiesConfig{
				Bypass: false,
				Add:    nil,
				Drop:   nil,
			},
			expected: []string{
				"bypass=false",
			},
		},
		{
			name: "bypass true",
			config: CapabilitiesConfig{
				Bypass: true,
				Add:    nil,
				Drop:   nil,
			},
			expected: []string{
				"bypass=true",
			},
		},
		{
			name: "only add capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add: []string{
					"CAP_NET_ADMIN",
					"CAP_SYS_ADMIN",
				},
				Drop: nil,
			},
			expected: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"add=CAP_SYS_ADMIN",
			},
		},
		{
			name: "only drop capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add:    nil,
				Drop: []string{
					"CAP_NET_RAW",
					"CAP_DAC_OVERRIDE",
				},
			},
			expected: []string{
				"bypass=false",
				"drop=CAP_NET_RAW",
				"drop=CAP_DAC_OVERRIDE",
			},
		},
		{
			name: "add and drop capabilities",
			config: CapabilitiesConfig{
				Bypass: false,
				Add: []string{
					"CAP_NET_ADMIN",
				},
				Drop: []string{
					"CAP_NET_RAW",
				},
			},
			expected: []string{
				"bypass=false",
				"add=CAP_NET_ADMIN",
				"drop=CAP_NET_RAW",
			},
		},
		{
			name: "bypass with capabilities",
			config: CapabilitiesConfig{
				Bypass: true,
				Add: []string{
					"CAP_NET_ADMIN",
				},
				Drop: []string{
					"CAP_NET_RAW",
				},
			},
			expected: []string{
				"bypass=true",
				"add=CAP_NET_ADMIN",
				"drop=CAP_NET_RAW",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.flags()
			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPrepareCapabilities(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		flags          []string
		expectedReturn config.CapabilitiesConfig
		expectedError  string
	}{
		// default values (no flags)
		{
			testName: "default values",
			flags:    []string{},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		// valid bypass flags
		{
			testName: "bypass=true",
			flags:    []string{"bypass=true"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: true,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "bypass=false",
			flags:    []string{"bypass=false"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "bypass=1",
			flags:    []string{"bypass=1"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: true,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "bypass=0",
			flags:    []string{"bypass=0"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		// valid add flags
		{
			testName: "single add capability",
			flags:    []string{"add=CAP_NET_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN"},
				DropCaps:   nil,
			},
		},
		{
			testName: "multiple add capabilities",
			flags:    []string{"add=CAP_NET_ADMIN", "add=CAP_SYS_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"},
				DropCaps:   nil,
			},
		},
		{
			testName: "add capability with comma-separated values",
			flags:    []string{"add=CAP_NET_ADMIN,CAP_SYS_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"},
				DropCaps:   nil,
			},
		},
		// valid drop flags
		{
			testName: "single drop capability",
			flags:    []string{"drop=CAP_NET_RAW"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW"},
			},
		},
		{
			testName: "multiple drop capabilities",
			flags:    []string{"drop=CAP_NET_RAW", "drop=CAP_DAC_OVERRIDE"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW", "CAP_DAC_OVERRIDE"},
			},
		},
		{
			testName: "drop capability with comma-separated values",
			flags:    []string{"drop=CAP_NET_RAW,CAP_DAC_OVERRIDE"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW", "CAP_DAC_OVERRIDE"},
			},
		},
		// valid multiple flags
		{
			testName: "bypass with add capabilities",
			flags:    []string{"bypass=true", "add=CAP_NET_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: true,
				AddCaps:    []string{"CAP_NET_ADMIN"},
				DropCaps:   nil,
			},
		},
		{
			testName: "bypass with drop capabilities",
			flags:    []string{"bypass=false", "drop=CAP_NET_RAW"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW"},
			},
		},
		{
			testName: "add and drop different capabilities",
			flags:    []string{"add=CAP_NET_ADMIN", "drop=CAP_NET_RAW"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN"},
				DropCaps:   []string{"CAP_NET_RAW"},
			},
		},
		{
			testName: "all flags combined",
			flags:    []string{"bypass=true", "add=CAP_NET_ADMIN,CAP_SYS_ADMIN", "drop=CAP_NET_RAW"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: true,
				AddCaps:    []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"},
				DropCaps:   []string{"CAP_NET_RAW"},
			},
		},
		{
			testName: "flags in different order",
			flags:    []string{"drop=CAP_NET_RAW", "bypass=false", "add=CAP_NET_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN"},
				DropCaps:   []string{"CAP_NET_RAW"},
			},
		},
		// invalid bypass values
		{
			testName:       "invalid bypass value",
			flags:          []string{"bypass=invalid"},
			expectedReturn: config.CapabilitiesConfig{},
			expectedError:  "bypass should either be true or false",
		},
		{
			testName:       "invalid bypass value empty",
			flags:          []string{"bypass="},
			expectedReturn: config.CapabilitiesConfig{},
			expectedError:  "bypass should either be true or false",
		},
		// invalid: add and drop same capability
		{
			testName:       "add and drop same capability",
			flags:          []string{"add=CAP_NET_ADMIN", "drop=CAP_NET_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{},
			expectedError:  "cant add and drop CAP_NET_ADMIN at the same time",
		},
		{
			testName:       "add and drop same capability in comma-separated",
			flags:          []string{"add=CAP_NET_ADMIN,CAP_SYS_ADMIN", "drop=CAP_NET_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{},
			expectedError:  "cant add and drop CAP_NET_ADMIN at the same time",
		},
		// edge cases
		{
			testName: "empty add value",
			flags:    []string{"add="},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "empty drop value",
			flags:    []string{"drop="},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "add with empty values in comma-separated",
			flags:    []string{"add=CAP_NET_ADMIN,,CAP_SYS_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"},
				DropCaps:   nil,
			},
		},
		{
			testName: "drop with empty values in comma-separated",
			flags:    []string{"drop=CAP_NET_RAW,,CAP_DAC_OVERRIDE"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW", "CAP_DAC_OVERRIDE"},
			},
		},
		// duplicate flags (last one wins for bypass)
		{
			testName: "duplicate bypass flags",
			flags:    []string{"bypass=false", "bypass=true"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: true,
				AddCaps:    nil,
				DropCaps:   nil,
			},
		},
		{
			testName: "duplicate add flags accumulate",
			flags:    []string{"add=CAP_NET_ADMIN", "add=CAP_SYS_ADMIN"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"},
				DropCaps:   nil,
			},
		},
		{
			testName: "duplicate drop flags accumulate",
			flags:    []string{"drop=CAP_NET_RAW", "drop=CAP_DAC_OVERRIDE"},
			expectedReturn: config.CapabilitiesConfig{
				BypassCaps: false,
				AddCaps:    nil,
				DropCaps:   []string{"CAP_NET_RAW", "CAP_DAC_OVERRIDE"},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			caps, err := PrepareCapabilities(tc.flags)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReturn.BypassCaps, caps.BypassCaps)
				assert.Equal(t, tc.expectedReturn.AddCaps, caps.AddCaps)
				assert.Equal(t, tc.expectedReturn.DropCaps, caps.DropCaps)
			}
		})
	}
}
