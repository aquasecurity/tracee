package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignaturesConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   SignaturesConfig
		expected []string
	}{
		{
			name: "empty config",
			config: SignaturesConfig{
				SearchPaths: []string{},
			},
			expected: []string{},
		},
		{
			name: "single search path",
			config: SignaturesConfig{
				SearchPaths: []string{"/path/to/signatures"},
			},
			expected: []string{
				"search-paths=/path/to/signatures",
			},
		},
		{
			name: "multiple search paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"/path/to/signatures1,/path/to/signatures2,/opt/tracee/signatures",
				},
			},
			expected: []string{
				"search-paths=/path/to/signatures1,/path/to/signatures2,/opt/tracee/signatures",
			},
		},
		{
			name: "relative paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"./signatures",
					"../other/signatures",
				},
			},
			expected: []string{
				"search-paths=./signatures,../other/signatures",
			},
		},
		{
			name: "mixed absolute and relative paths",
			config: SignaturesConfig{
				SearchPaths: []string{
					"/usr/local/signatures",
					"./local/signatures",
					"/opt/tracee/signatures",
				},
			},
			expected: []string{
				"search-paths=/usr/local/signatures,./local/signatures,/opt/tracee/signatures",
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

func TestPrepareSignatures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		signatures     []string
		expectedConfig SignaturesConfig
		expectedError  string
	}{
		{
			name:       "empty signatures",
			signatures: []string{},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{},
			},
		},
		{
			name:       "single search path",
			signatures: []string{"search-paths=/path/to/signatures"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path/to/signatures"},
			},
		},
		{
			name:       "multiple search paths",
			signatures: []string{"search-paths=/path1,/path2,/path3"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path1", "/path2", "/path3"},
			},
		},
		{
			name:       "multiple search paths with spaces",
			signatures: []string{"search-paths=/path1, /path2 , /path3"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path1", "/path2", "/path3"},
			},
		},
		{
			name:       "multiple flags with same key",
			signatures: []string{"search-paths=/path1", "search-paths=/path2"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path1", "/path2"},
			},
		},
		{
			name:       "search paths with empty values filtered",
			signatures: []string{"search-paths=/path1,,/path2"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path1", "/path2"},
			},
		},
		{
			name:          "invalid flag format - no equals",
			signatures:    []string{"search-paths"},
			expectedError: "flags.PrepareSignatures: invalid signatures flag: search-paths, use 'trace man signatures' for more info",
		},
		{
			name:       "invalid flag format - multiple equals",
			signatures: []string{"search-paths=/path1=/path2"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/path1=/path2"},
			},
		},
		{
			name:          "invalid flag key",
			signatures:    []string{"invalid-key=/path"},
			expectedError: "flags.PrepareSignatures: invalid signatures flag: invalid-key=/path, use 'trace man signatures' for more info",
		},
		{
			name:          "empty search-paths value",
			signatures:    []string{"search-paths="},
			expectedError: "flags.PrepareSignatures: invalid signatures flag: search-paths value can't be empty, use 'trace man signatures' for more info",
		},
		{
			name:       "search paths with relative paths",
			signatures: []string{"search-paths=./signatures,../other/signatures"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"./signatures", "../other/signatures"},
			},
		},
		{
			name:       "search paths with absolute paths",
			signatures: []string{"search-paths=/usr/local/signatures,/opt/tracee/signatures"},
			expectedConfig: SignaturesConfig{
				SearchPaths: []string{"/usr/local/signatures", "/opt/tracee/signatures"},
			},
		},
		{
			name:          "mixed valid and invalid flags",
			signatures:    []string{"search-paths=/path1", "invalid-flag=value"},
			expectedError: "flags.PrepareSignatures: invalid signatures flag: invalid-flag=value, use 'trace man signatures' for more info",
		},
		{
			name:          "invalid flag name empty",
			signatures:    []string{"=/path"},
			expectedError: "flags.PrepareSignatures: invalid signatures flag: =/path, use 'trace man signatures' for more info",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config, err := PrepareSignatures(tt.signatures)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
				assert.Empty(t, config.SearchPaths)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig.SearchPaths, config.SearchPaths, "SearchPaths should match")
			}
		})
	}
}
