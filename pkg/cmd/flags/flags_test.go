package flags

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/signatures/rego"
)

func TestParseFilterFlag(t *testing.T) {
	testCases := []struct {
		name           string
		flag           string
		expectedResult *filterFlag
		expectedError  error
	}{
		// Valid
		{
			name: "Valid flag without operatorAndValues",
			flag: "filterName",
			expectedResult: &filterFlag{
				full:              "filterName",
				filterName:        "filterName",
				operatorAndValues: "",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag without operatorAndValues",
			flag: "!filterName",
			expectedResult: &filterFlag{
				full:              "!filterName",
				filterName:        "!filterName",
				operatorAndValues: "",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName=v",
			expectedResult: &filterFlag{
				full:              "filterName=v",
				filterName:        "filterName",
				operatorAndValues: "=v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName!=v",
			expectedResult: &filterFlag{
				full:              "filterName!=v",
				filterName:        "filterName",
				operatorAndValues: "!=v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>v",
			expectedResult: &filterFlag{
				full:              "filterName>v",
				filterName:        "filterName",
				operatorAndValues: ">v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<v",
			expectedResult: &filterFlag{
				full:              "filterName<v",
				filterName:        "filterName",
				operatorAndValues: "<v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>=v",
			expectedResult: &filterFlag{
				full:              "filterName>=v",
				filterName:        "filterName",
				operatorAndValues: ">=v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<=v",
			expectedResult: &filterFlag{
				full:              "filterName<=v",
				filterName:        "filterName",
				operatorAndValues: "<=v",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName=value",
			expectedResult: &filterFlag{
				full:              "filterName=value",
				filterName:        "filterName",
				operatorAndValues: "=value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName!=value",
			expectedResult: &filterFlag{
				full:              "filterName!=value",
				filterName:        "filterName",
				operatorAndValues: "!=value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>value",
			expectedResult: &filterFlag{
				full:              "filterName>value",
				filterName:        "filterName",
				operatorAndValues: ">value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<value",
			expectedResult: &filterFlag{
				full:              "filterName<value",
				filterName:        "filterName",
				operatorAndValues: "<value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName>=value",
			expectedResult: &filterFlag{
				full:              "filterName>=value",
				filterName:        "filterName",
				operatorAndValues: ">=value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},
		{
			name: "Valid flag with operatorAndValues",
			flag: "filterName<=value",
			expectedResult: &filterFlag{
				full:              "filterName<=value",
				filterName:        "filterName",
				operatorAndValues: "<=value",
				policyIdx:         0,
				policyName:        "",
			},
			expectedError: nil,
		},

		// Invalid flag
		{
			name:           "Invalid flag - empty",
			flag:           "",
			expectedResult: nil,
			expectedError:  InvalidFlagEmpty(),
		},
		// Invalid operator
		{
			name:           "Invalid operator",
			flag:           "filterName==value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName==value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName=!value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName=!value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName!!value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName!!value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName>>value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName>>value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName<>value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName<>value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName>!value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName>!value"),
		},
		{
			name:           "Invalid operator",
			flag:           "filterName!<value",
			expectedResult: nil,
			expectedError:  InvalidFlagOperator("filterName!<value"),
		},
		// Invalid value
		{
			name:           "Invalid value",
			flag:           "filterName=",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName="),
		},
		{
			name:           "Invalid value",
			flag:           "filterName!=",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName!="),
		},
		{
			name:           "Invalid value",
			flag:           "filterName<",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName<"),
		},
		{
			name:           "Invalid value",
			flag:           "filterName>",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName>"),
		},
		{
			name:           "Invalid value",
			flag:           "filterName>=",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName>="),
		},
		{
			name:           "Invalid value",
			flag:           "filterName<=",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName<="),
		},
		{
			name:           "Invalid value",
			flag:           "filterName< value",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName< value"),
		},
		{
			name:           "Invalid value",
			flag:           "filterName>=value ",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName>=value "),
		},
		{
			name:           "Invalid value",
			flag:           "filterName=\tvalue",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName=\tvalue"),
		},
		{
			name:           "Invalid value",
			flag:           "filterName=value\t",
			expectedResult: nil,
			expectedError:  InvalidFlagValue("filterName=value\t"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseFilterFlag(tt.flag)
			if err != nil {
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestCreatePolicies(t *testing.T) {
	testCases := []struct {
		testName      string
		filters       []string
		expectedError error
	}{
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
			expectedError: InvalidFilterOptionError("open.bla=5"),
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
			expectedError: InvalidFilterOptionError("blabla=5"),
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
			expectedError: InvalidFilterOptionError("uid\t0"),
		},
		{
			testName:      "invalid operator",
			filters:       []string{"mntns\t0"},
			expectedError: InvalidFilterOptionError("mntns\t0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"UID>0"},
			expectedError: InvalidFilterOptionError("UID>0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"test=0"},
			expectedError: InvalidFilterOptionError("test=0"),
		},
		{
			testName:      "invalid filter type",
			filters:       []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"},
			expectedError: InvalidFilterOptionError("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=0"),
		},
		{
			testName:      "invalid mntns 2",
			filters:       []string{"mntns=-1"},
			expectedError: filters.InvalidValue("-1"),
		},
		{
			testName:      "invalid uid 1",
			filters:       []string{"uid=4294967296"},
			expectedError: filters.InvalidValue("4294967296"),
		},
		{
			testName:      "invalid uid 2",
			filters:       []string{"uid=-1"},
			expectedError: filters.InvalidValue("-1"),
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
			testName: "container",
			filters:  []string{"container"},
		},
		{
			testName: "container=new",
			filters:  []string{"container=new"},
		},
		{
			testName: "pid=new",
			filters:  []string{"pid=new"},
		},
		{
			testName: "container=abcd123",
			filters:  []string{"container=abcd123"},
		},
		{
			testName: "argfilter",
			filters:  []string{"openat.pathname=/bin/ls,/tmp/tracee", "openat.pathname!=/etc/passwd"},
		},
		{
			testName: "retfilter",
			filters:  []string{"openat.retval=2", "openat.retval>1"},
		},
		{
			testName: "wildcard filter",
			filters:  []string{"event=open*"},
		},
		{
			testName: "wildcard not filter",
			filters:  []string{"event!=*"},
		},
		{
			testName: "multiple filters",
			filters:  []string{"uid<1", "mntns=5", "pidns!=3", "pid!=10", "comm=ps", "uts!=abc"},
		},
		{
			testName:      "invalid value - string in numeric filter",
			filters:       []string{"uid=a"},
			expectedError: filters.InvalidValue("a"),
		},
		{
			testName:      "invalid pidns",
			filters:       []string{"pidns=a"},
			expectedError: filters.InvalidValue("a"),
		},

		{
			testName: "valid pid",
			filters:  []string{"pid>12"},
		},
		{
			testName: "adding retval filter then argfilter",
			filters:  []string{"open.retval=5", "security_file_open.pathname=/etc/shadow"},
		},
		{
			testName:      "invalid wildcard",
			filters:       []string{"event=blah*"},
			expectedError: errors.New("invalid event to trace: blah"),
		},
		{
			testName:      "invalid wildcard 2",
			filters:       []string{"event=bl*ah"},
			expectedError: errors.New("invalid event to trace: bl*ah"),
		},
		{
			testName:      "internal event selection",
			filters:       []string{"event=print_syscall_table"},
			expectedError: errors.New("invalid event to trace: print_syscall_table"),
		},
		{
			testName:      "invalid not wildcard",
			filters:       []string{"event!=blah*"},
			expectedError: errors.New("invalid event to exclude: blah"),
		},
		{
			testName:      "invalid not wildcard 2",
			filters:       []string{"event!=bl*ah"},
			expectedError: errors.New("invalid event to exclude: bl*ah"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			filterMap, err := PrepareFilterMapFromFlags(tc.filters)
			assert.NoError(t, err)

			_, err = CreatePolicies(filterMap)
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
				testName:     "capture bpf",
				captureSlice: []string{"bpf"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					Bpf:        true,
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
			},
			{
				testName:     "multiple capture options",
				captureSlice: []string{"write", "exec", "mem", "module", "bpf"},
				expectedCapture: tracee.CaptureConfig{
					OutputPath: "/tmp/tracee/out",
					FileWrite:  true,
					Mem:        true,
					Exec:       true,
					Module:     true,
					Bpf:        true,
				},
			},
		}
		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				capture, err := PrepareCapture(tc.captureSlice)
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
		capture, err := PrepareCapture([]string{fmt.Sprintf("dir:%s", d.Name()), "clear-dir"})
		require.NoError(t, err)
		assert.Equal(t, tracee.CaptureConfig{OutputPath: fmt.Sprintf("%s/out", d.Name())}, capture)
		require.NoDirExists(t, d.Name()+"out")
	})
}

func TestPrepareTraceeEbpfOutput(t *testing.T) {
	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput OutputConfig
		expectedError  error
	}{
		{
			testName:    "invalid output option",
			outputSlice: []string{"foo"},
			// it's not the preparer job to validate input. in this case foo is considered an implicit output format.
			expectedError: errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:      "invalid output option",
			outputSlice:   []string{"option:"},
			expectedError: errors.New("invalid output option: , use '--output help' for more info"),
		},
		{
			testName:      "invalid output option 2",
			outputSlice:   []string{"option:foo"},
			expectedError: errors.New("invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty val",
			outputSlice:   []string{"out-file"},
			expectedError: errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table format always parse arguments",
			outputSlice: []string{"table"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					StackAddresses: true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option relative-time",
			outputSlice: []string{"json", "option:relative-time"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					RelativeTime: true,
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ExecHash:       true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments",
			outputSlice: []string{"json", "option:parse-arguments"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments-fds",
			outputSlice: []string{"json", "option:parse-arguments-fds"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments:    true,
					ParseArgumentsFDs: true,
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
		},
		{
			testName: "all options",
			outputSlice: []string{
				"json",
				"option:stack-addresses",
				"option:exec-env",
				"option:relative-time",
				"option:exec-hash",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			expectedOutput: OutputConfig{
				TraceeConfig: &tracee.OutputConfig{
					StackAddresses:    true,
					ExecEnv:           true,
					RelativeTime:      true,
					ExecHash:          true,
					ParseArguments:    true,
					ParseArgumentsFDs: true,
					EventsSorting:     true,
				},
			},
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, err := TraceeEbpfPrepareOutput(testcase.outputSlice)
			if err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.TraceeConfig, output.TraceeConfig)
			}
		})
	}
}

func TestPrepareOutput(t *testing.T) {
	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput OutputConfig
		expectedError  error
	}{
		// validations
		{
			testName:      "invalid output flag",
			outputSlice:   []string{"foo"},
			expectedError: errors.New("invalid output flag: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty option flag",
			outputSlice:   []string{"option"},
			expectedError: errors.New("parseOption: option flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty option flag 2",
			outputSlice:   []string{"option:"},
			expectedError: errors.New("parseOption: option flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid option value",
			outputSlice:   []string{"option:foo"},
			expectedError: errors.New("setOption: invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty file for format",
			outputSlice:   []string{"json:"},
			expectedError: errors.New("parseFormat: format flag can't be empty, use '--output help' for more info"),
		},
		// formats
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to stdout",
			outputSlice: []string{"table"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to /tmp/table",
			outputSlice: []string{"table:/tmp/table"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "/tmp/table"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table to stdout, and to /tmp/table",
			outputSlice: []string{"table", "table:/tmp/table"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
					{Kind: "table", OutPath: "/tmp/table"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "json to stdout",
			outputSlice: []string{"json"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "json to /tmp/json, and json to /tmp/json2",
			outputSlice: []string{"json:/tmp/json", "json:/tmp/json2"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "/tmp/json"},
					{Kind: "json", OutPath: "/tmp/json2"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "gob to stdout",
			outputSlice: []string{"gob"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "gob", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "gob to stdout",
			outputSlice: []string{"gob"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "gob", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "gob to /tmp/gob1,/tmp/gob2",
			outputSlice: []string{"gob:/tmp/gob1,/tmp/gob2"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "gob", OutPath: "/tmp/gob1"},
					{Kind: "gob", OutPath: "/tmp/gob2"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "table-verbose to stdout",
			outputSlice: []string{"table-verbose"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table-verbose", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to stdout",
			outputSlice: []string{"gotemplate=template.tmpl"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "gotemplate=template.tmpl", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:    "gotemplate to multiple files",
			outputSlice: []string{"gotemplate=template.tmpl:/tmp/gotemplate1,/tmp/gotemplate2"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate1"},
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate2"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName: "multiple formats",
			outputSlice: []string{
				"table",
				"json:/tmp/json,/tmp/json2",
				"gob:/tmp/gob1",
				"gotemplate=template.tmpl:/tmp/gotemplate1",
			},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
					{Kind: "json", OutPath: "/tmp/json"},
					{Kind: "json", OutPath: "/tmp/json2"},
					{Kind: "gob", OutPath: "/tmp/gob1"},
					{Kind: "gotemplate=template.tmpl", OutPath: "/tmp/gotemplate1"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:      "two formats for stdout",
			outputSlice:   []string{"table", "json"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: stdout, use '--output help' for more info"),
		},
		{
			testName:      "format for the same file twice",
			outputSlice:   []string{"table:/tmp/test,/tmp/test"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: /tmp/test, use '--output help' for more info"),
		},
		{
			testName:      "two different formats for the same file",
			outputSlice:   []string{"table:/tmp/test", "json:/tmp/test"},
			expectedError: errors.New("parseFormat: cannot use the same path for multiple outputs: /tmp/test, use '--output help' for more info"),
		},
		{
			testName:    "none",
			outputSlice: []string{"none"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "ignore", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		{
			testName:      "invalid value for none format",
			outputSlice:   []string{"none:"},
			expectedError: errors.New("none output does not support path. Use '--output help' for more info"),
		},
		{
			testName:      "invalid value for none format 2",
			outputSlice:   []string{"none:/tmp/test"},
			expectedError: errors.New("none output does not support path. Use '--output help' for more info"),
		},
		// forward
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward"},
			expectedError: errors.New("validateURL: forward flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty forward flag",
			outputSlice:   []string{"forward:"},
			expectedError: errors.New("validateURL: forward flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid forward url",
			outputSlice:   []string{"forward:lalala"},
			expectedError: errors.New("validateURL: invalid uri for forward output \"lalala\". Use '--output help' for more info"),
		},
		{
			testName:    "forward",
			outputSlice: []string{"forward:tcp://localhost:1234"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "forward", OutPath: "tcp://localhost:1234"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		// webhook
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook"},
			expectedError: errors.New("validateURL: webhook flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "empty webhook flag",
			outputSlice:   []string{"webhook:"},
			expectedError: errors.New("validateURL: webhook flag can't be empty, use '--output help' for more info"),
		},
		{
			testName:      "invalid webhook url",
			outputSlice:   []string{"webhook:lalala"},
			expectedError: errors.New("validateURL: invalid uri for webhook output \"lalala\". Use '--output help' for more info"),
		},
		{
			testName:    "webhook",
			outputSlice: []string{"webhook:http://localhost:8080"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "webhook", OutPath: "http://localhost:8080"},
				},
				TraceeConfig: &tracee.OutputConfig{},
			},
		},
		// options
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					StackAddresses: true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option relative-time",
			outputSlice: []string{"json", "option:relative-time"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "stdout", RelativeTS: true},
				},
				TraceeConfig: &tracee.OutputConfig{
					RelativeTime: true,
				},
			},
		},
		{
			testName:    "option exec-hash",
			outputSlice: []string{"option:exec-hash"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ExecHash:       true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments",
			outputSlice: []string{"json", "option:parse-arguments"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments-fds",
			outputSlice: []string{"json", "option:parse-arguments-fds"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments:    true,
					ParseArgumentsFDs: true,
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "table", OutPath: "stdout"},
				},
				TraceeConfig: &tracee.OutputConfig{
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
		},
		{
			testName: "all options",
			outputSlice: []string{
				"json",
				"option:stack-addresses",
				"option:exec-env",
				"option:relative-time",
				"option:exec-hash",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			expectedOutput: OutputConfig{
				PrinterConfigs: []printer.Config{
					{Kind: "json", OutPath: "stdout", RelativeTS: true},
				},
				TraceeConfig: &tracee.OutputConfig{
					StackAddresses:    true,
					ExecEnv:           true,
					RelativeTime:      true,
					ExecHash:          true,
					ParseArguments:    true,
					ParseArgumentsFDs: true,
					EventsSorting:     true,
				},
			},
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			output, err := PrepareOutput(testcase.outputSlice)
			if err != nil {
				assert.Contains(t, err.Error(), testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.TraceeConfig, output.TraceeConfig)

				assertPrinterConfigs(t, testcase.expectedOutput.PrinterConfigs, output.PrinterConfigs)

			}
		})
	}
}

func assertPrinterConfigs(t *testing.T, expected []printer.Config, actual []printer.Config) {
	// use a map to compare because the order of the printers is not guaranteed
	printersMap := make(map[string]printer.Config)

	for _, p := range expected {
		printersMap[p.OutPath] = p
	}

	for _, p := range actual {
		expectedPrinter, ok := printersMap[p.OutPath]
		assert.True(t, ok)

		assert.Equal(t, expectedPrinter.Kind, p.Kind)
		assert.Equal(t, expectedPrinter.OutPath, p.OutPath)
		assert.Equal(t, expectedPrinter.RelativeTS, p.RelativeTS)
		assert.Equal(t, expectedPrinter.ContainerMode, p.ContainerMode)
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
			cache, err := PrepareCache(testcase.cacheSlice)
			if testcase.expectedError != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			}
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
				rego, err := PrepareRego(tc.regoSlice)
				if tc.expectedError == nil {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedRego, rego, tc.testName)
				} else {
					assert.ErrorContains(t, err, tc.expectedError.Error(), tc.testName)
					assert.Empty(t, rego, tc.testName)
				}
			})
		}
	})
}
