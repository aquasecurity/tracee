package flags_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/rules/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This will only test failure cases since success cases are covered in the filter tests themselves
func TestPrepareFilterScope(t *testing.T) {
	testCases := []struct {
		testName      string
		filters       []string
		expectedError error
	}{
		{
			testName:      "invalid scope id 1",
			filters:       []string{":comm=bash"},
			expectedError: filters.InvalidScope(":comm=bash"),
		},
		{
			testName:      "invalid scope id 2",
			filters:       []string{"0:comm=bash"},
			expectedError: filters.InvalidScope("0:comm=bash"),
		},
		{
			testName:      "invalid scope id 3",
			filters:       []string{fmt.Sprintf("%d:comm=bash", tracee.MaxFilterScopes+1)},
			expectedError: filters.InvalidScope(fmt.Sprintf("%d:comm=bash", tracee.MaxFilterScopes+1)),
		},
		{
			testName:      "invalid argfilter 1",
			filters:       []string{"open.args"},
			expectedError: filters.InvalidExpression("open."),
		},
		{
			testName:      "invalid argfilter 2",
			filters:       []string{"open.args.bla=5"},
			expectedError: filters.InvalidEventArgument("bla"),
		},
		{
			testName:      "invalid argfilter 3",
			filters:       []string{"open.bla=5"},
			expectedError: flags.InvalidFilterOptionError("open.bla=5"),
		},
		{
			testName:      "invalid context filter 1",
			filters:       []string{"open.context"},
			expectedError: filters.InvalidExpression("open.context"),
		},
		{
			testName:      "invalid context filter 2",
			filters:       []string{"bla.context.processName=ls"},
			expectedError: filters.InvalidEventName("bla"),
		},
		{
			testName:      "invalid context filter 3",
			filters:       []string{"openat.context.procName=ls"},
			expectedError: filters.InvalidContextField("procName"),
		},
		{
			testName:      "invalid filter",
			filters:       []string{"blabla=5"},
			expectedError: flags.InvalidFilterOptionError("blabla=5"),
		},
		{
			testName:      "invalid retfilter 1",
			filters:       []string{".retval"},
			expectedError: filters.InvalidExpression(".retval"),
		},
		{
			testName:      "invalid retfilter 2",
			filters:       []string{"open.retvall=5"},
			expectedError: filters.InvalidExpression("open.retvall=5"),
		},
		{
			testName:      "invalid operator",
			filters:       []string{"uid\t0"},
			expectedError: flags.InvalidFilterOptionError("uid\t0"),
		},
		{
			testName:      "invalid operator",
			filters:       []string{"mntns\t0"},
			expectedError: flags.InvalidFilterOptionError("mntns\t0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"UID>0"},
			expectedError: flags.InvalidFilterOptionError("UID>0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"test=0"},
			expectedError: flags.InvalidFilterOptionError("test=0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"},
			expectedError: flags.InvalidFilterOptionError("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"),
		},
		{
			testName:      "invalid mntns 1",
			filters:       []string{"mntns="},
			expectedError: filters.InvalidExpression("mntns="),
		},
		{
			testName:      "invalid mntns 2",
			filters:       []string{"mntns=-1"},
			expectedError: filters.InvalidValue("-1"),
		},
		{
			testName:      "invalid uid 1",
			filters:       []string{"uid=\t"},
			expectedError: filters.InvalidValue("\t"),
		},
		{
			testName:      "invalid uid 2",
			filters:       []string{"uid=4294967296"},
			expectedError: filters.InvalidValue("4294967296"),
		},
		{
			testName:      "invalid uid 3",
			filters:       []string{"uid=-1"},
			expectedError: filters.InvalidValue("-1"),
		},
		{
			testName:      "invalid uid 4",
			filters:       []string{"uid=-1\t"},
			expectedError: filters.InvalidValue("-1\t"),
		},
		{
			testName: "success - scope 1",
			filters:  []string{"10:uid=4294967296"},
		},
		{
			testName: "success - scope 2",
			filters:  []string{"25:pid>50000"},
		},
		{
			testName: "success - large uid filter",
			filters:  []string{"uid=4294967296"},
		},
		{
			testName: "success - pid greater or large",
			filters:  []string{"pid>=12"},
		},
		{
			testName: "success - uid=0",
			filters:  []string{"uid=0"},
		},
		{
			testName: "success - uid!=0",
			filters:  []string{"uid!=0"},
		},
		{
			testName: "success - mntns=0",
			filters:  []string{"mntns=0"},
		},
		{
			testName: "success - pidns!=0",
			filters:  []string{"pidns!=0"},
		},
		{
			testName: "success - comm=ls",
			filters:  []string{"comm=ls"},
		},
		{
			testName: "success - binary=host:/usr/bin/ls",
			filters:  []string{"binary=host:/usr/bin/ls"},
		},
		{
			testName: "success - binary=/usr/bin/ls",
			filters:  []string{"binary=/usr/bin/ls"},
		},
		{
			testName: "success - scope 2:binary=host:/usr/bin/ls",
			filters:  []string{"2:binary=host:/usr/bin/ls"},
		},
		{
			testName: "success - uts!=deadbeaf",
			filters:  []string{"uts!=deadbeaf"},
		},
		{
			testName: "success - uid>0",
			filters:  []string{"uid>0"},
		},
		{
			testName: "success - uid<0",
			filters:  []string{"uid<0"},
		},
		{
			testName:      "invalid - uid>=",
			filters:       []string{"uid>="},
			expectedError: filters.InvalidExpression("uid>="),
		},
		{
			testName: "container",
			filters:  []string{"container"},
		},
		{
			testName: "2:container",
			filters:  []string{"2:container"},
		},
		{
			testName: "container=new",
			filters:  []string{"container=new"},
		},
		{
			testName: "2:container=new",
			filters:  []string{"2:container=new"},
		},
		{
			testName: "pid=new",
			filters:  []string{"pid=new"},
		},
		{
			testName: "2:pid=new",
			filters:  []string{"2:pid=new"},
		},
		{
			testName: "container=abcd123",
			filters:  []string{"container=abcd123"},
		},
		{
			testName: "2:container=abcd123",
			filters:  []string{"2:container=abcd123"},
		},
		{
			testName: "argfilter",
			filters:  []string{"openat.pathname=/bin/ls,/tmp/tracee", "openat.pathname!=/etc/passwd"},
		},
		{
			testName: "argfilter scope",
			filters:  []string{"2:openat.pathname=/bin/ls,/tmp/tracee", "2:openat.pathname!=/etc/passwd"},
		},
		{
			testName: "retfilter",
			filters:  []string{"openat.retval=2", "openat.retval>1"},
		},
		{
			testName: "retfilter scope",
			filters:  []string{"2:openat.retval=2", "2:openat.retval>1"},
		},
		{
			testName: "wildcard filter",
			filters:  []string{"event=open*"},
		},
		{
			testName: "wildcard filter scope",
			filters:  []string{"2:event=open*"},
		},
		{
			testName: "wildcard not filter",
			filters:  []string{"event!=*"},
		},
		{
			testName: "wildcard not filter scope",
			filters:  []string{"2:event!=*"},
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc"},
		},
		{
			testName: "multiple filters scope",
			filters:  []string{"2:uid<1", "2:mntns=5", "2:pidns!=3", "2:pid!=10", "2:comm=ps", "2:uts!=abc"},
		},
		{
			testName:      "invalid value - extra operator",
			filters:       []string{"uid==0"},
			expectedError: filters.InvalidValue("=0"),
		},
		{
			testName:      "invalid value scope - extra operator",
			filters:       []string{"2:uid==0"},
			expectedError: filters.InvalidValue("=0"),
		},
		{
			testName:      "invalid value - extra operator",
			filters:       []string{"uid>>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"},
			expectedError: filters.InvalidValue(">>>>>>>>>>>>>>>>>>>>>>>>>>>>0"),
		},
		{
			testName:      "invalid value scope - extra operator",
			filters:       []string{"2:uid>>>>>>>>>>>>>>>>>>>>>>>>>>>>>0"},
			expectedError: filters.InvalidValue(">>>>>>>>>>>>>>>>>>>>>>>>>>>>0"),
		},
		{
			testName:      "invalid value - string in numeric filter",
			filters:       []string{"uid=a"},
			expectedError: filters.InvalidValue("a"),
		},
		{
			testName:      "invalid value scope - string in numeric filter",
			filters:       []string{"2:uid=a"},
			expectedError: filters.InvalidValue("a"),
		},
		{
			testName:      "invalid pidns",
			filters:       []string{"pidns=a"},
			expectedError: filters.InvalidValue("a"),
		},
		{
			testName:      "invalid pidns scope",
			filters:       []string{"2:pidns=a"},
			expectedError: filters.InvalidValue("a"),
		},

		{
			testName: "valid pid",
			filters:  []string{"pid>12"},
		},
		{
			testName: "valid pid scope",
			filters:  []string{"2:pid>12"},
		},
		{
			testName: "adding retval filter then argfilter",
			filters:  []string{"open.retval=5", "security_file_open.pathname=/etc/shadow"},
		},
		{
			testName: "adding retval filter then argfilter scope",
			filters:  []string{"2:open.retval=5", "2:security_file_open.pathname=/etc/shadow"},
		},
		{
			testName:      "invalid wildcard",
			filters:       []string{"event=blah*"},
			expectedError: errors.New("invalid event to trace: blah"),
		},
		{
			testName:      "invalid wildcard scope",
			filters:       []string{"2:event=blah*"},
			expectedError: errors.New("invalid event to trace: blah"),
		},
		{
			testName:      "invalid wildcard 2",
			filters:       []string{"event=bl*ah"},
			expectedError: errors.New("invalid event to trace: bl*ah"),
		},
		{
			testName:      "invalid wildcard scope 2",
			filters:       []string{"2:event=bl*ah"},
			expectedError: errors.New("invalid event to trace: bl*ah"),
		},
		{
			testName:      "internal event selection",
			filters:       []string{"event=print_syscall_table"},
			expectedError: errors.New("invalid event to trace: print_syscall_table"),
		},
		{
			testName:      "internal event selection scope",
			filters:       []string{"2:event=print_syscall_table"},
			expectedError: errors.New("invalid event to trace: print_syscall_table"),
		},
		{
			testName:      "invalid not wildcard",
			filters:       []string{"event!=blah*"},
			expectedError: errors.New("invalid event to exclude: blah"),
		},
		{
			testName:      "invalid not wildcard scope",
			filters:       []string{"2:event!=blah*"},
			expectedError: errors.New("invalid event to exclude: blah"),
		},
		{
			testName:      "invalid not wildcard 2",
			filters:       []string{"event!=bl*ah"},
			expectedError: errors.New("invalid event to exclude: bl*ah"),
		},
		{
			testName:      "invalid not wildcard scope 2",
			filters:       []string{"2:event!=bl*ah"},
			expectedError: errors.New("invalid event to exclude: bl*ah"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			_, err := flags.PrepareFilterScopes(tc.filters)
			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedError.Error())
			}
		})
	}
}

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
			},
			{
				testName:     "capture exec",
				captureSlice: []string{"exec"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Exec:       true,
				},
			},
			{
				testName:     "capture module",
				captureSlice: []string{"module"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Module:     true,
				},
			},
			{
				testName:     "capture write",
				captureSlice: []string{"write"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  true,
				},
			},
			{
				testName:     "capture network with default pcap type",
				captureSlice: []string{"network"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Net: pcaps.Config{
						CaptureSingle: true,
						CaptureLength: 96,
					},
				},
			},
			{
				testName:     "capture network with all pcap types",
				captureSlice: []string{"network", "pcap:process,command,container"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Net: pcaps.Config{
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
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Net: pcaps.Config{
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
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Net: pcaps.Config{
						CaptureSingle:    false,
						CaptureProcess:   false,
						CaptureContainer: true,
						CaptureCommand:   true,
						CaptureLength:    120,
					},
				},
			},
			{
				testName:     "capture write filtered",
				captureSlice: []string{"write=/tmp*"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath:      "/tmp/tracee/out",
					FileWrite:       true,
					FilterFileWrite: []string{"/tmp"},
				},
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
		d, _ := os.CreateTemp("", "TestPrepareCapture-*")
		capture, err := flags.PrepareCapture([]string{fmt.Sprintf("dir:%s", d.Name()), "clear-dir"})
		require.NoError(t, err)
		assert.Equal(t, tracee.CaptureConfig{OutputPath: fmt.Sprintf("%s/out", d.Name())}, capture)
		require.NoDirExists(t, d.Name()+"out")
	})
}

func TestPrepareOutput(t *testing.T) {
	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput flags.OutputConfig
		expectedError  error
	}{
		{
			testName:    "invalid output option",
			outputSlice: []string{"foo"},
			// it's not the preparer job to validate input. in this case foo is considered an implicit output format.
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
			},
			expectedError: errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:    "invalid output option",
			outputSlice: []string{"option:"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
			},
			expectedError: errors.New("invalid output option: , use '--output help' for more info"),
		},
		{
			testName:    "invalid output option 2",
			outputSlice: []string{"option:foo"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
			},
			expectedError: errors.New("invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:    "empty val",
			outputSlice: []string{"out-file"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
			},
			expectedError: errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},

		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
				OutputConfig: tracee.OutputConfig{
					StackAddresses: true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
				OutputConfig: tracee.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
				OutputConfig: tracee.OutputConfig{
					ExecHash:       true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
				OutputConfig: tracee.OutputConfig{
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
		},
		{
			testName:    "all options",
			outputSlice: []string{"option:stack-addresses", "option:exec-env", "option:exec-hash", "option:sort-events"},
			expectedOutput: flags.OutputConfig{
				LogFile: os.Stderr,
				OutputConfig: tracee.OutputConfig{
					StackAddresses: true,
					ExecEnv:        true,
					ExecHash:       true,
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
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
		},
		{
			testName:      "cache-type=mem",
			cacheSlice:    []string{"cache-type=mem"},
			expectedCache: queue.NewEventQueueMem(0),
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

func TestPrepareRego(t *testing.T) {
	t.Run("various rego options", func(t *testing.T) {
		testCases := []struct {
			testName      string
			regoSlice     []string
			expectedRego  rego.Config
			expectedError error
		}{
			{
				testName:      "invalid rego option",
				regoSlice:     []string{"foo"},
				expectedError: errors.New("invalid rego option specified, use '--rego help' for more info"),
			},
			{
				testName:  "default options",
				regoSlice: []string{},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					PartialEval:   false,
					AIO:           false,
				},
			},
			{
				testName:  "configure partial-eval",
				regoSlice: []string{"partial-eval"},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					PartialEval:   true,
				},
			},
			{
				testName:  "configure aio",
				regoSlice: []string{"aio"},
				expectedRego: rego.Config{
					RuntimeTarget: "rego",
					AIO:           true,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				rego, err := flags.PrepareRego(tc.regoSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedRego, rego, tc.testName)
				} else {
					require.Equal(t, tc.expectedError, err, tc.testName)
					assert.Empty(t, rego, tc.testName)
				}
			})
		}
	})
}
