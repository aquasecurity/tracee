package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestParseArgs(t *testing.T) {
	t.Parallel()

	t.Run("Parse pointer value", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name         string
			args         []trace.Argument
			expectedArgs []trace.Argument
		}{
			{
				name: "ptrace addr arg",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "addr",
							Type: "void*",
						},
						Value: ^uintptr(0),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "addr",
							Type: "void*",
						},
						Value: "0xffffffffffffffff",
					},
				},
			},
			{
				name: "ptrace addr arg",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "addr",
							Type: "void*",
						},
						Value: uintptr(0x42424242),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "addr",
							Type: "void*",
						},
						Value: "0x42424242",
					},
				},
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				event := trace.Event{
					EventID: int(Ptrace),
					Args:    testCase.args,
				}
				err := ParseArgs(&event)
				require.NoError(t, err)
				for _, expArg := range testCase.expectedArgs {
					arg := GetArg(&event, expArg.Name)
					assert.Equal(t, expArg, *arg)
				}
			})
		}
	})

	t.Run("Parse setsockopt value", func(t *testing.T) {
		t.Parallel()

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
						Value: int32(parsers.SO_LOCK_FILTER.Value()),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "int",
						},
						Value: int32(parsers.SOL_IP.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: parsers.SO_LOCK_FILTER.String(),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "string",
						},
						Value: parsers.SOL_IP.String(),
					},
				},
			},
			{
				name: "SO_ATTACH_FILTER optname",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "int",
						},
						Value: int32(parsers.SO_ATTACH_FILTER.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: "SO_ATTACH_FILTER",
					},
				},
			},
			{
				name: "normal optname",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "int",
						},
						Value: int32(parsers.SO_LOCK_FILTER.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: parsers.SO_LOCK_FILTER.String(),
					},
				},
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				event := trace.Event{
					EventID: int(Setsockopt),
					Args:    testCase.args,
				}
				err := ParseArgs(&event)
				require.NoError(t, err)
				for _, expArg := range testCase.expectedArgs {
					arg := GetArg(&event, expArg.Name)
					assert.Equal(t, expArg, *arg)
				}
			})
		}
	})

	t.Run("Parse getsockopt value", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name         string
			args         []trace.Argument
			expectedArgs []trace.Argument
		}{
			{
				name: "normal optname",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "int",
						},
						Value: int32(parsers.SO_LOCK_FILTER.Value()),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "int",
						},
						Value: int32(parsers.SOL_IP.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: parsers.SO_LOCK_FILTER.String(),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "string",
						},
						Value: parsers.SOL_IP.String(),
					},
				},
			},
			{
				name: "SO_GET_FILTER optname",
				args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "int",
						},
						Value: int32(parsers.SO_GET_FILTER.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: "SO_GET_FILTER",
					},
				},
			},
		}

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				event := &trace.Event{
					EventID: int(Getsockopt),
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
	})
}
