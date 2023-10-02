package flags

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/config"
)

func TestPrepareCapture(t *testing.T) {
	t.Parallel()

	t.Run("various capture options", func(t *testing.T) {
		testCases := []struct {
			testName        string
			captureSlice    []string
			expectedCapture config.CaptureConfig
			expectedError   error
		}{
			{
				testName:        "invalid capture option",
				captureSlice:    []string{"foo"},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
			},
			{
				testName:      "invalid capture dir",
				captureSlice:  []string{"dir:"},
				expectedError: errors.New("capture output dir cannot be empty"),
			},
			{
				testName:        "invalid capture write filter",
				captureSlice:    []string{"write="},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
			},
			{
				testName:        "invalid capture write filter 2",
				captureSlice:    []string{"write=/tmp"},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("file path filter should end with *"),
			},
			{
				testName:        "empty capture write filter",
				captureSlice:    []string{"write=*"},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("capture path filter cannot be empty"),
			},
			{
				testName:        "non existing capture write type filter",
				captureSlice:    []string{"write:type=non-existing"},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("unsupported file type filter value for capture - non-existing"),
			},
			{
				testName:        "non existing capture write fds filter",
				captureSlice:    []string{"write:fd=non-existing"},
				expectedCapture: config.CaptureConfig{},
				expectedError:   errors.New("unsupported file FD filter value for capture - non-existing"),
			},
			{
				testName:     "capture mem",
				captureSlice: []string{"mem"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Mem:        true,
				},
			},
			{
				testName:     "capture exec",
				captureSlice: []string{"exec"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
				},
			},
			{
				testName:     "capture module",
				captureSlice: []string{"module"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Module:     true,
				},
			},
			{
				testName:     "capture write",
				captureSlice: []string{"write"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileCaptureConfig{
						Capture: true,
					},
				},
			},
			{
				testName:     "capture network with default pcap type",
				captureSlice: []string{"network"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Net: config.PcapsConfig{
						CaptureSingle: true,
						CaptureLength: 96,
					},
				},
			},
			{
				testName:     "capture network with all pcap types",
				captureSlice: []string{"network", "pcap:process,command,container"},
				expectedCapture: config.CaptureConfig{
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
				testName:     "capture network with multiple pcap types",
				captureSlice: []string{"network", "pcap:command,container"},
				expectedCapture: config.CaptureConfig{
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
				testName:     "capture network with multiple pcap types and snaplen",
				captureSlice: []string{"network", "pcap:command,container", "pcap-snaplen:120b"},
				expectedCapture: config.CaptureConfig{
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
				testName:     "capture bpf",
				captureSlice: []string{"bpf"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Bpf:        true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture write filtered",
				captureSlice: []string{"write=/tmp*"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite: config.FileCaptureConfig{
						Capture:    true,
						PathFilter: []string{"/tmp"},
					},
				},
			},
			{
				testName:     "capture read",
				captureSlice: []string{"read"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileCaptureConfig{
						Capture: true,
					},
				},
			},
			{
				testName:     "capture read filtered by path",
				captureSlice: []string{"read:path=/tmp*"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileCaptureConfig{
						Capture:    true,
						PathFilter: []string{"/tmp"},
					},
				},
			},
			{
				testName:     "capture read filtered by type",
				captureSlice: []string{"read:type=pipe"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileCaptureConfig{
						Capture:    true,
						TypeFilter: config.CapturePipeFiles,
					},
				},
			},
			{
				testName:     "capture read filtered by fd",
				captureSlice: []string{"read:fd=stdin"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileRead: config.FileCaptureConfig{
						Capture:    true,
						TypeFilter: config.CaptureStdinFiles,
					},
				},
			},
			{
				testName:     "multiple capture options",
				captureSlice: []string{"write", "exec", "mem", "module", "bpf"},
				expectedCapture: config.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  config.FileCaptureConfig{Capture: true},
					Mem:        true,
					Exec:       true,
					Module:     true,
					Bpf:        true,
				},
			},
		}
		for _, tc := range testCases {
			tc := tc

			t.Run(tc.testName, func(t *testing.T) {
				t.Parallel()

				capture, err := PrepareCapture(tc.captureSlice, false)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedCapture, capture, tc.testName)
				} else {
					assert.ErrorContains(t, err, tc.expectedError.Error(), tc.testName)
					assert.Empty(t, capture, tc.testName)
				}
			})
		}
	})

	t.Run("clear dir", func(t *testing.T) {
		d, _ := os.CreateTemp("", "TestPrepareCapture-*")
		capture, err := PrepareCapture([]string{fmt.Sprintf("dir:%s", d.Name()), "clear-dir"}, false)
		require.NoError(t, err)
		assert.Equal(t, config.CaptureConfig{OutputPath: fmt.Sprintf("%s/out", d.Name())}, capture)
		require.NoDirExists(t, d.Name()+"out")
	})
}
