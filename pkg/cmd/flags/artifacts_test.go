package flags

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/config"
)

func TestPrepareArtifacts(t *testing.T) {
	t.Parallel()

	t.Run("various artifacts options", func(t *testing.T) {
		testCases := []struct {
			testName          string
			artifactsSlice    []string
			expectedArtifacts config.ArtifactsConfig
			expectedError     error
		}{
			{
				testName:       "invalid artifacts option - no dot",
				artifactsSlice: []string{"foo"},
				expectedError:  errfmt.Errorf("invalid artifacts option: %s, run 'tracee man artifacts' for more info", "foo"),
			},
			{
				testName:       "invalid artifacts option - invalid suboption",
				artifactsSlice: []string{"executable.invalid"},
				expectedError:  errfmt.Errorf("invalid artifacts option: %s, run 'tracee man artifacts' for more info", "executable.invalid"),
			},
			{
				testName:       "artifacts file-write with filters auto-enables",
				artifactsSlice: []string{"file-write.filters=path=/tmp*"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileArtifactsConfig{
						Capture:    true,
						PathFilter: []string{"/tmp"},
					},
				},
			},
			{
				testName:       "artifacts file-read with filters auto-enables",
				artifactsSlice: []string{"file-read.filters=path=/etc*"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileArtifactsConfig{
						Capture:    true,
						PathFilter: []string{"/etc"},
					},
				},
			},
			{
				testName:       "invalid file-write option - invalid suboption",
				artifactsSlice: []string{"file-write.invalid"},
				expectedError:  errfmt.Errorf("invalid file %s option: %s", "write", "invalid"),
			},
			{
				testName:       "invalid artifacts dir - empty path",
				artifactsSlice: []string{"dir.path="},
				expectedError:  errfmt.Errorf("artifacts output dir cannot be empty"),
			},
			{
				testName:       "invalid file-write filter - empty",
				artifactsSlice: []string{"file-write.filters="},
				expectedError:  errfmt.Errorf("file write filter cannot be empty"),
			},
			{
				testName:       "invalid file-write filter - no asterisk",
				artifactsSlice: []string{"file-write.filters=path=/tmp"},
				expectedError:  errors.New("file path filter should end with *"),
			},
			{
				testName:       "invalid file-write filter - empty path",
				artifactsSlice: []string{"file-write.filters=path=*"},
				expectedError:  errors.New("artifacts path filter cannot be empty"),
			},
			{
				testName:       "invalid file-write type filter",
				artifactsSlice: []string{"file-write.filters=type=non-existing"},
				expectedError:  errors.New("unsupported file type filter value for artifacts - non-existing"),
			},
			{
				testName:       "invalid file-write fd filter",
				artifactsSlice: []string{"file-write.filters=fd=non-existing"},
				expectedError:  errors.New("unsupported file FD filter value for artifacts - non-existing"),
			},
			{
				testName:       "artifacts memory-regions enabled",
				artifactsSlice: []string{"memory-regions"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Mem:        true,
				},
			},
			{
				testName:       "artifacts executable enabled",
				artifactsSlice: []string{"executable"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
				},
			},
			{
				testName:       "artifacts kernel-modules enabled",
				artifactsSlice: []string{"kernel-modules"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Module:     true,
				},
			},
			{
				testName:       "artifacts file-write enabled",
				artifactsSlice: []string{"file-write"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileArtifactsConfig{
						Capture: true,
					},
				},
			},
			{
				testName:       "artifacts network enabled",
				artifactsSlice: []string{"network"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: 96,
					},
				},
			},
			{
				testName:       "artifacts network with pcap split",
				artifactsSlice: []string{"network.pcap.split=process,command,container"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle:    false,
						CaptureProcess:   true,
						CaptureContainer: true,
						CaptureCommand:   true,
						CaptureLength:    96,
					},
				},
			},
			{
				testName:       "artifacts network with multiple pcap split types",
				artifactsSlice: []string{"network.pcap.split=command,container"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle:    false,
						CaptureProcess:   false,
						CaptureContainer: true,
						CaptureCommand:   true,
						CaptureLength:    96,
					},
				},
			},
			{
				testName:       "artifacts network with pcap split and snaplen",
				artifactsSlice: []string{"network.pcap.split=command,container", "network.pcap.snaplen=120b"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle:    false,
						CaptureProcess:   false,
						CaptureContainer: true,
						CaptureCommand:   true,
						CaptureLength:    120,
					},
				},
			},
			{
				testName:       "artifacts network with pcap options filtered",
				artifactsSlice: []string{"network.pcap.options=filtered"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle:   true,
						CaptureFiltered: true,
						CaptureLength:   96,
					},
				},
			},
			{
				testName:       "artifacts network with pcap options none",
				artifactsSlice: []string{"network.pcap.options=none"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle:   true,
						CaptureFiltered: false,
						CaptureLength:   96,
					},
				},
			},
			{
				testName:       "artifacts network with pcap snaplen max",
				artifactsSlice: []string{"network.pcap.snaplen=max"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: (1 << 16) - 1,
					},
				},
			},
			{
				testName:       "artifacts network with pcap snaplen headers",
				artifactsSlice: []string{"network.pcap.snaplen=headers"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: 0,
					},
				},
			},
			{
				testName:       "artifacts network with pcap snaplen default",
				artifactsSlice: []string{"network.pcap.snaplen=default"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: 96,
					},
				},
			},
			{
				testName:       "artifacts network with pcap snaplen kb",
				artifactsSlice: []string{"network.pcap.snaplen=1kb"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: 1024,
					},
				},
			},
			{
				testName:       "artifacts bpf-programs enabled",
				artifactsSlice: []string{"bpf-programs"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					Bpf:        true,
				},
			},
			{
				testName:       "artifacts file-write filtered by path",
				artifactsSlice: []string{"file-write.filters=path=/tmp*"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileArtifactsConfig{
						Capture:    true,
						PathFilter: []string{"/tmp"},
					},
				},
			},
			{
				testName:       "artifacts file-read enabled",
				artifactsSlice: []string{"file-read"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileArtifactsConfig{
						Capture: true,
					},
				},
			},
			{
				testName:       "artifacts file-read filtered by path",
				artifactsSlice: []string{"file-read.filters=path=/tmp*"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileArtifactsConfig{
						Capture:    true,
						PathFilter: []string{"/tmp"},
					},
				},
			},
			{
				testName:       "artifacts file-read filtered by type",
				artifactsSlice: []string{"file-read.filters=type=pipe"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileArtifactsConfig{
						Capture:    true,
						TypeFilter: config.ArtifactsPipeFiles,
					},
				},
			},
			{
				testName:       "artifacts file-read filtered by fd",
				artifactsSlice: []string{"file-read.filters=fd=stdin"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileArtifactsConfig{
						Capture:    true,
						TypeFilter: config.ArtifactsStdinFiles,
					},
				},
			},
			{
				testName:       "artifacts file-write filtered by type",
				artifactsSlice: []string{"file-write.filters=type=socket"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileArtifactsConfig{
						Capture:    true,
						TypeFilter: config.ArtifactsSocketFiles,
					},
				},
			},
			{
				testName:       "artifacts file-write filtered by fd",
				artifactsSlice: []string{"file-write.filters=fd=stdout"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileArtifactsConfig{
						Capture:    true,
						TypeFilter: config.ArtifactsStdoutFiles,
					},
				},
			},
			{
				testName:       "multiple artifacts options",
				artifactsSlice: []string{"file-write", "executable", "memory-regions", "kernel-modules", "bpf-programs"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  config.FileArtifactsConfig{Capture: true},
					Mem:        true,
					Exec:       true,
					Module:     true,
					Bpf:        true,
				},
			},
			{
				testName:       "artifacts dir path",
				artifactsSlice: []string{"dir.path=/custom/path"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/custom/path/out",
				},
			},
			{
				testName:       "artifacts dir clear",
				artifactsSlice: []string{"dir.clear"},
				expectedArtifacts: config.ArtifactsConfig{
					OutputPath: "/tmp/tracee/out",
				},
			},
			{
				testName:       "artifacts invalid pcap split mode",
				artifactsSlice: []string{"network.pcap.split=invalid"},
				expectedError:  errfmt.Errorf("invalid pcap split mode: invalid"),
			},
			{
				testName:       "artifacts invalid pcap options",
				artifactsSlice: []string{"network.pcap.options=invalid"},
				expectedError:  errfmt.Errorf("invalid pcap options value: invalid (must be 'none' or 'filtered')"),
			},
			{
				testName:       "artifacts invalid pcap snaplen",
				artifactsSlice: []string{"network.pcap.snaplen=invalid"},
				expectedError:  errfmt.Errorf("could not parse pcap snaplen: missing b or kb ?"),
			},
		}
		for _, tc := range testCases {
			tc := tc

			t.Run(tc.testName, func(t *testing.T) {
				t.Parallel()

				artifactsConfig, err := PrepareArtifacts(tc.artifactsSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					artifacts := artifactsConfig.GetArtifactsConfig()
					assert.Equal(t, tc.expectedArtifacts, artifacts, tc.testName)
				} else {
					require.Error(t, err)
					// Extract just the error message without function prefix
					expectedMsg := tc.expectedError.Error()
					// Remove common prefixes that errfmt adds
					expectedMsg = strings.TrimPrefix(expectedMsg, "flags.TestPrepareArtifacts.func1: ")
					assert.Contains(t, err.Error(), expectedMsg, tc.testName)
					assert.Empty(t, artifactsConfig, tc.testName)
				}
			})
		}
	})

	t.Run("clear dir", func(t *testing.T) {
		d, _ := os.CreateTemp("", "TestPrepareArtifacts-*")
		artifactsConfig, err := PrepareArtifacts([]string{fmt.Sprintf("dir.path=%s", d.Name()), "dir.clear"})
		require.NoError(t, err)
		artifacts := artifactsConfig.GetArtifactsConfig()
		assert.Equal(t, config.ArtifactsConfig{OutputPath: fmt.Sprintf("%s/out", d.Name())}, artifacts)
		require.NoDirExists(t, d.Name()+"out")
	})
}
