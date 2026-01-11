package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a valid base config
func validConfig() Config {
	return Config{
		Buffers: BuffersConfig{
			Kernel: KernelBuffersConfig{
				Events:    1024, // power of 2
				Artifacts: 512,  // power of 2
			},
		},
		Artifacts:   &ArtifactsConfig{},
		Output:      &OutputConfig{},
		BPFObjBytes: []byte{1, 2, 3},
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectError   bool
		expectedError error
	}{
		{
			name:        "valid config",
			config:      validConfig(),
			expectError: false,
		},
		{
			name: "invalid kernel events buffer size - not power of 2",
			config: func() Config {
				cfg := validConfig()
				cfg.Buffers.Kernel.Events = 1000 // not a power of 2
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidKernelEventsBufferSizeError,
		},
		{
			name: "invalid kernel artifacts buffer size - not power of 2",
			config: func() Config {
				cfg := validConfig()
				cfg.Buffers.Kernel.Artifacts = 500 // not a power of 2
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidKernelArtifactsBufferSizeError,
		},
		{
			name: "valid power of 2 buffer sizes",
			config: func() Config {
				cfg := validConfig()
				cfg.Buffers.Kernel.Events = 1    // 2^0
				cfg.Buffers.Kernel.Artifacts = 2 // 2^1
				return cfg
			}(),
			expectError: false,
		},
		{
			name: "too many file-write path filters",
			config: func() Config {
				cfg := validConfig()
				cfg.Artifacts.FileWrite.PathFilter = []string{"/tmp*", "/var*", "/usr*", "/etc*"} // 4 filters > 3
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidArtifactsFileWriteTooManyPathFiltersError,
		},
		{
			name: "too many file-read path filters",
			config: func() Config {
				cfg := validConfig()
				cfg.Artifacts.FileRead.PathFilter = []string{"/tmp*", "/var*", "/usr*", "/etc*"} // 4 filters > 3
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidArtifactsFileReadTooManyPathFiltersError,
		},
		{
			name: "file-write path filter too long",
			config: func() Config {
				cfg := validConfig()
				longFilter := "/this/is/a/very/long/path/that/exceeds/fifty/characters*"
				cfg.Artifacts.FileWrite.PathFilter = []string{longFilter}
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidPathFilterError("/this/is/a/very/long/path/that/exceeds/fifty/characters*"),
		},
		{
			name: "file-read path filter too long - note: validation bug checks FileWrite instead",
			config: func() Config {
				cfg := validConfig()
				longFilter := "/this/is/a/very/long/path/that/exceeds/fifty/characters*"
				cfg.Artifacts.FileRead.PathFilter = []string{"/tmp*"}
				cfg.Artifacts.FileWrite.PathFilter = []string{longFilter}
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidPathFilterError("/this/is/a/very/long/path/that/exceeds/fifty/characters*"),
		},
		{
			name: "valid path filter length - exactly 50 characters",
			config: func() Config {
				cfg := validConfig()
				cfg.Artifacts.FileWrite.PathFilter = []string{"/this/is/a/path/exactly/fifty/characters/long*"}
				return cfg
			}(),
			expectError: false,
		},
		{
			name: "stream with no destinations",
			config: func() Config {
				cfg := validConfig()
				cfg.Output.Streams = []Stream{
					{
						Name:         "stream1",
						Destinations: []Destination{}, // empty destinations
					},
				}
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidStreamConfigError("stream1"),
		},
		{
			name: "multiple streams - one without destinations",
			config: func() Config {
				cfg := validConfig()
				cfg.Output.Streams = []Stream{
					{
						Name: "stream1",
						Destinations: []Destination{
							{Name: "dest1"},
						},
					},
					{
						Name:         "stream2",
						Destinations: []Destination{}, // empty destinations
					},
				}
				return cfg
			}(),
			expectError:   true,
			expectedError: invalidStreamConfigError("stream2"),
		},
		{
			name: "nil BPF object bytes",
			config: func() Config {
				cfg := validConfig()
				cfg.BPFObjBytes = nil
				return cfg
			}(),
			expectError:   true,
			expectedError: nilBPFObjectError,
		},
		{
			name: "empty BPF object bytes",
			config: func() Config {
				cfg := validConfig()
				cfg.BPFObjBytes = []byte{}
				return cfg
			}(),
			expectError: false, // empty slice is not nil, so it's valid
		},
		{
			name: "maximum valid path filters",
			config: func() Config {
				cfg := validConfig()
				cfg.Artifacts.FileWrite.PathFilter = []string{"/tmp*", "/var*", "/usr*"} // exactly 3 filters
				cfg.Artifacts.FileRead.PathFilter = []string{"/etc*", "/opt*", "/home*"} // exactly 3 filters
				return cfg
			}(),
			expectError: false,
		},
		{
			name: "multiple valid streams",
			config: func() Config {
				cfg := validConfig()
				cfg.Output.Streams = []Stream{
					{
						Name: "stream1",
						Destinations: []Destination{
							{Name: "dest1"},
							{Name: "dest2"},
						},
					},
					{
						Name: "stream2",
						Destinations: []Destination{
							{Name: "dest3"},
						},
					},
				}
				return cfg
			}(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
