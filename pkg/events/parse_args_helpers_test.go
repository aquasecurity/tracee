package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestParseArgsHelpers(t *testing.T) {
	t.Parallel()
	TestParseMMapProt(t)
	TestParseSocketDomainArgument(t)
	TestParseSocketType(t)
	TestParseInodeMode(t)
	TestParseBPFProgType(t)
	TestParseCapability(t)
	TestParseMemProtAlert(t)
	TestParseSyscall(t)
	TestParsePtraceRequestArgument(t)
	TestParsePrctlOption(t)
	TestParseSocketcallCall(t)
	TestParseAccessMode(t)
	TestParseExecveatFlag(t)
	TestParseOpenFlagArgument(t)
	TestParseCloneFlags(t)
	TestParseBPFCmd(t)
	TestParseSocketLevel(t)
	TestParseGetSocketOption(t)
	TestParseFsNotifyObjType(t)
	TestParseBpfHelpersUsage(t)
	TestParseBpfAttachType(t)
}
func TestParseMMapProt(t *testing.T) {
	// No need to add other test cases because there isn't a case where parseMMapProt fail
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{{
		name: "normal flow",
		args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "prot",
					Type: "int",
				},
				Value: parsers.PROT_READ.Value(),
			},
		},
		expectedArgs: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "prot",
					Type: "string",
				},
				Value: "PROT_READ",
			},
		},
	},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseMMapProt(GetArg(event, "prot"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseSocketDomainArgument(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "domain",
						Type: "int",
					},
					Value: parsers.AF_INET.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "domain",
						Type: "string",
					},
					Value: "AF_INET",
				},
			},
		},
		{
			name: "invalid domain",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "domain",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "domain",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseSocketDomainArgument(GetArg(event, "domain"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseSocketType(t *testing.T) {
	testCases := []struct {
		eventId      int
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name:    "normal flow",
			eventId: int(Socket),
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "int",
					},
					Value: int32(parsers.SOCK_STREAM.Value()),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "string",
					},
					Value: "SOCK_STREAM",
				},
			},
		},
		{
			name:    "invalid type",
			eventId: int(Socket),
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "int",
					},
					Value: int32(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				EventID: testCase.eventId,
				Args:    testCase.args,
			}
			err := ParseArgs(event)
			require.NoError(t, err)
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseInodeMode(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "int",
					},
					Value: parsers.S_IFSOCK.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "string",
					},
					Value: "S_IFSOCK",
				},
			},
		},
		{
			name: "invalid mode",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "int",
					},
					Value: uint64(0),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "string",
					},
					Value: "",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseInodeMode(GetArg(event, "mode"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseBPFProgType(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "int",
					},
					Value: parsers.BPFProgTypeUnspec.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "string",
					},
					Value: "BPF_PROG_TYPE_UNSPEC",
				},
			},
		},
		{
			name: "invalid type",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "type",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseBPFProgType(GetArg(event, "type"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseCapability(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "capability",
						Type: "int",
					},
					Value: parsers.CAP_CHOWN.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "capability",
						Type: "string",
					},
					Value: "CAP_CHOWN",
				},
			},
		},
		{
			name: "invalid capability",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "capability",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "capability",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseCapability(GetArg(event, "capability"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseMemProtAlert(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "alert",
						Type: "int",
					},
					Value: uint32(trace.ProtAlertMmapWX),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "alert",
						Type: "string",
					},
					Value: "Mmaped region with W+E permissions!",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseMemProtAlert(GetArg(event, "alert"), testCase.args[0].Value.(uint32))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseSyscall(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "id",
						Type: "int",
					},
					Value: int32(Ptrace),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "id",
						Type: "string",
					},
					Value: "ptrace",
				},
			},
		},
		{
			name: "invalid syscall",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "id",
						Type: "int",
					},
					Value: int32(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "id",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseSyscall(GetArg(event, "id"), testCase.args[0].Value.(int32))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParsePtraceRequestArgument(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "req",
						Type: "int",
					},
					Value: parsers.PTRACE_PEEKTEXT.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "req",
						Type: "string",
					},
					Value: "PTRACE_PEEKTEXT",
				},
			},
		},
		{
			name: "invalid req",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "req",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "req",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parsePtraceRequestArgument(GetArg(event, "req"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParsePrctlOption(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "opt",
						Type: "int",
					},
					Value: parsers.PR_SET_NO_NEW_PRIVS.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "opt",
						Type: "string",
					},
					Value: "PR_SET_NO_NEW_PRIVS",
				},
			},
		},
		{
			name: "invalid opt",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "opt",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "opt",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parsePrctlOption(GetArg(event, "opt"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseSocketcallCall(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "call",
						Type: "int",
					},
					Value: parsers.SYS_SOCKET.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "call",
						Type: "string",
					},
					Value: "SYS_SOCKET",
				},
			},
		},
		{
			name: "invalid call",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "call",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "call",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseSocketcallCall(GetArg(event, "call"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseAccessMode(t *testing.T) {
	testcase := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		// TODO: remove comment when tracee handles an empty flag, will be fixed in #4279
		// {
		// 	name: "normal flow",
		// 	args: []trace.Argument{
		// 		{
		// 			ArgMeta: trace.ArgMeta{
		// 				Name: "mode",
		// 				Type: "int",
		// 			},
		// 			Value: parsers.F_OK.Value(),
		// 		},
		// 	},
		// 	expectedArgs: []trace.Argument{
		// 		{
		// 			ArgMeta: trace.ArgMeta{
		// 				Name: "mode",
		// 				Type: "string",
		// 			},
		// 			Value: "F_OK",
		// 		},
		// 	},
		// },
		{
			name: "multiple flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "int",
					},
					Value: parsers.X_OK.Value() | parsers.R_OK.Value() | parsers.W_OK.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "string",
					},
					Value: "X_OK|W_OK|R_OK",
				},
			},
		},
	}

	for _, testCase := range testcase {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseAccessMode(GetArg(event, "mode"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseExecveatFlag(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: parsers.AT_SYMLINK_NOFOLLOW.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "AT_SYMLINK_NOFOLLOW",
				},
			},
		},
		{
			name: "invalid flags",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: uint64(100),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "100",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseExecveatFlag(GetArg(event, "flags"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseOpenFlagArgument(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		// TODO: remove comment when tracee handles an empty flag, will be fixed in #4279
		// {
		// 	name: "normal flow",
		// 	args: []trace.Argument{
		// 		{
		// 			ArgMeta: trace.ArgMeta{
		// 				Name: "flags",
		// 				Type: "int",
		// 			},
		// 			Value: parsers.O_RDONLY.Value(),
		// 		},
		// 	},
		// 	expectedArgs: []trace.Argument{
		// 		{
		// 			ArgMeta: trace.ArgMeta{
		// 				Name: "flags",
		// 				Type: "string",
		// 			},
		// 			Value: "O_RDONLY",
		// 		},
		// 	},
		// },
		{
			name: "multiple flags",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: parsers.O_RDWR.Value() | parsers.O_CREAT.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "O_RDWR|O_CREAT",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseOpenFlagArgument(GetArg(event, "flags"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseCloneFlags(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: parsers.CLONE_VM.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "CLONE_VM",
				},
			},
		},
		{
			name: "multiple flags",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: parsers.CLONE_VM.Value() | parsers.CLONE_FS.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "CLONE_VM|CLONE_FS",
				},
			},
		},
		{
			name: "zero flags",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "int",
					},
					Value: uint64(0),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "flags",
						Type: "string",
					},
					Value: "",
				},
			},
		},
	}
	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseCloneFlags(GetArg(event, "flags"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseBPFCmd(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "cmd",
						Type: "int",
					},
					Value: parsers.BPF_PROG_LOAD.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "cmd",
						Type: "string",
					},
					Value: "BPF_PROG_LOAD",
				},
			},
		},
		{
			name: "invalid cmd",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "cmd",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "cmd",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseBPFCmd(GetArg(event, "cmd"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseSocketLevel(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "level",
						Type: "int",
					},
					Value: parsers.SOL_SOCKET.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "level",
						Type: "string",
					},
					Value: "SOL_SOCKET",
				},
			},
		},
		{
			name: "invalid level",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "level",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "level",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseSocketLevel(GetArg(event, "level"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseGetSocketOption(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "optname",
						Type: "int",
					},
					Value: parsers.SO_LOCK_FILTER.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "optname",
						Type: "string",
					},
					Value: "SO_LOCK_FILTER",
				},
			},
		},
		{
			name: "invalid flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "optname",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "optname",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseGetSocketOption(GetArg(event, "optname"), testCase.args[0].Value.(uint64), Getsockopt)
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseFsNotifyObjType(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "objType",
						Type: "int",
					},
					Value: parsers.FSNOTIFY_OBJ_TYPE_INODE.Value(),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "objType",
						Type: "string",
					},
					Value: "FSNOTIFY_OBJ_TYPE_INODE",
				},
			},
		},
		{
			name: "invalid objType",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "objType",
						Type: "int",
					},
					Value: uint64(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "objType",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseFsNotifyObjType(GetArg(event, "objType"), testCase.args[0].Value.(uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseBpfHelpersUsage(t *testing.T) {
	var emptyValue []string
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "helpersList",
						Type: "int",
					},
					Value: []uint64{1, 2, 3},
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "helpersList",
						Type: "const char**",
					},
					Value: []string{"unspec", "xdp_adjust_tail", "sk_cgroup_id", "sk_ancestor_cgroup_id"},
				},
			},
		},
		{
			name: "invalid helpersList",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "helpersList",
						Type: "int",
					},
					Value: []uint64{0},
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "helpersList",
						Type: "const char**",
					},
					Value: emptyValue,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseBpfHelpersUsage(GetArg(event, "helpersList"), testCase.args[0].Value.([]uint64))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
func TestParseBpfAttachType(t *testing.T) {
	testCases := []struct {
		name         string
		args         []trace.Argument
		expectedArgs []trace.Argument
	}{
		{
			name: "normal flow",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "attachType",
						Type: "int",
					},
					Value: int32(0),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "attachType",
						Type: "string",
					},
					Value: "raw_tracepoint",
				},
			},
		},
		{
			name: "invalid attachType",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "attachType",
						Type: "int",
					},
					Value: int32(12345),
				},
			},
			expectedArgs: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "attachType",
						Type: "string",
					},
					Value: "12345",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			event := &trace.Event{
				Args: testCase.args,
			}
			parseBpfAttachType(GetArg(event, "attachType"), testCase.args[0].Value.(int32))
			for _, expArg := range testCase.expectedArgs {
				arg := GetArg(event, expArg.Name)
				assert.Equal(t, expArg, *arg)
			}
		})
	}
}
