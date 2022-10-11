package flags_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareCapture(t *testing.T) {
	t.Run("various capture options", func(t *testing.T) {
		testCases := []struct {
			testName        string
			captureSlice    []string
			expectedCapture tracee.CaptureConfig
			expectedError   error
		}{
			{
				testName:        "invalid capture option",
				captureSlice:    []string{"foo"},
				expectedCapture: tracee.CaptureConfig{},
				expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
			},
			{
				testName:      "invalid capture dir",
				captureSlice:  []string{"dir:"},
				expectedError: errors.New("capture output dir cannot be empty"),
			},
			{
				testName:      "invalid network interface",
				captureSlice:  []string{"net=invalidnetinterface"},
				expectedError: errors.New("invalid network interface: invalidnetinterface"),
			},
			{
				testName:        "invalid capture write filter",
				captureSlice:    []string{"write="},
				expectedCapture: tracee.CaptureConfig{},
				expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
			},
			{
				testName:        "invalid capture write filter 2",
				captureSlice:    []string{"write=/tmp"},
				expectedCapture: tracee.CaptureConfig{},
				expectedError:   errors.New("invalid capture option specified, use '--capture help' for more info"),
			},
			{
				testName:        "empty capture write filter",
				captureSlice:    []string{"write=*"},
				expectedCapture: tracee.CaptureConfig{},
				expectedError:   errors.New("capture write filter cannot be empty"),
			},
			{
				testName:     "capture mem",
				captureSlice: []string{"mem"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Mem:        true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture exec",
				captureSlice: []string{"exec"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture module",
				captureSlice: []string{"module"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Module:     true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture write",
				captureSlice: []string{"write"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture write filtered",
				captureSlice: []string{"write=/tmp*"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath:      "/tmp/tracee/out",
					FileWrite:       true,
					FilterFileWrite: []string{"/tmp"},
				},
				expectedError: nil,
			},
			{
				testName:     "multiple capture options",
				captureSlice: []string{"write", "exec", "mem", "module"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  true,
					Mem:        true,
					Exec:       true,
					Module:     true,
				},
				expectedError: nil,
			},
			{
				testName:     "capture exec and enable profile",
				captureSlice: []string{"exec", "profile"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
					Profile:    true,
				},
				expectedError: nil,
			},
			{
				testName:     "just enable profile",
				captureSlice: []string{"profile"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
					Profile:    true,
				},
				expectedError: nil,
			},
			{
				testName:     "network interface",
				captureSlice: []string{"net=lo"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					NetIfaces: &tracee.NetIfaces{
						Ifaces: []string{"lo"},
					},
				},
			},
			{
				testName:     "network interface, but repeated",
				captureSlice: []string{"net=lo", "net=lo"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					NetIfaces: &tracee.NetIfaces{
						Ifaces: []string{"lo"},
					},
				},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				capture, err := flags.PrepareCapture(tc.captureSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedCapture, capture, tc.testName)
				} else {
					require.Equal(t, tc.expectedError, err, tc.testName)
					assert.Empty(t, capture, tc.testName)
				}
			})
		}
	})

	t.Run("clear dir", func(t *testing.T) {
		d, _ := ioutil.TempDir("", "TestPrepareCapture-*")
		capture, err := flags.PrepareCapture([]string{fmt.Sprintf("dir:%s", d), "clear-dir"})
		require.NoError(t, err)
		assert.Equal(t, tracee.CaptureConfig{OutputPath: fmt.Sprintf("%s/out", d)}, capture)
		require.NoDirExists(t, d+"out")
	})
}

func TestPrepareOutput(t *testing.T) {

	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput tracee.OutputConfig
		expectedError  error
	}{
		{
			testName:    "invalid output option",
			outputSlice: []string{"foo"},
			// it's not the preparer job to validate input. in this case foo is considered an implicit output format.
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:       "invalid output option",
			outputSlice:    []string{"option:"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: , use '--output help' for more info"),
		},
		{
			testName:       "invalid output option 2",
			outputSlice:    []string{"option:foo"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:       "empty val",
			outputSlice:    []string{"out-file"},
			expectedOutput: tracee.OutputConfig{},
			expectedError:  errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option detect-syscall",
			outputSlice: []string{"option:detect-syscall"},
			expectedOutput: tracee.OutputConfig{
				DetectSyscall:  true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: tracee.OutputConfig{
				ExecEnv:        true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: tracee.OutputConfig{
				ExecHash:       true,
				ParseArguments: true,
			},
			expectedError: nil,
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: tracee.OutputConfig{
				ParseArguments: true,
				EventsSorting:  true,
			},
			expectedError: nil,
		},
		{
			testName:    "all options",
			outputSlice: []string{"option:stack-addresses", "option:detect-syscall", "option:exec-env", "option:exec-hash", "option:sort-events"},
			expectedOutput: tracee.OutputConfig{
				StackAddresses: true,
				DetectSyscall:  true,
				ExecEnv:        true,
				ExecHash:       true,
				ParseArguments: true,
				EventsSorting:  true,
			},
			expectedError: nil,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, _, err := flags.PrepareOutput(testcase.outputSlice)
			if err != nil {
				assert.Equal(t, testcase.expectedError, err)
			} else {
				assert.Equal(t, testcase.expectedOutput, output)
			}
		})
	}
}

func TestPrepareCache(t *testing.T) {
	testCases := []struct {
		testName      string
		cacheSlice    []string
		expectedCache queue.CacheConfig
		expectedError error
	}{
		{
			testName:      "invalid cache option",
			cacheSlice:    []string{"foo"},
			expectedCache: nil,
			expectedError: errors.New("unrecognized cache option format: foo"),
		},
		{
			testName:      "invalid cache-type",
			cacheSlice:    []string{"cache-type=bleh"},
			expectedCache: nil,
			expectedError: errors.New("unrecognized cache-mem option: cache-type=bleh (valid options are: none,mem)"),
		},
		{
			testName:      "cache-type=none",
			cacheSlice:    []string{"cache-type=none"},
			expectedCache: nil,
			expectedError: nil,
		},
		{
			testName:      "cache-type=mem",
			cacheSlice:    []string{"cache-type=mem"},
			expectedCache: queue.NewEventQueueMem(0),
			expectedError: nil,
		},
		{
			testName:      "mem-cache-size=X without cache-type=mem",
			cacheSlice:    []string{"mem-cache-size=256"},
			expectedCache: nil,
			expectedError: errors.New("you need to specify cache-type=mem before setting mem-cache-size"),
		},
		{
			testName:      "cache-type=mem with mem-cache-size=512",
			cacheSlice:    []string{"cache-type=mem", "mem-cache-size=512"},
			expectedCache: queue.NewEventQueueMem(512),
			expectedError: nil,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			cache, err := flags.PrepareCache(testcase.cacheSlice)
			assert.Equal(t, testcase.expectedError, err)
			assert.Equal(t, testcase.expectedCache, cache)
		})
	}
}
