package events

import (
	"testing"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	t.Run("Parse setsockopt value", func(t *testing.T) {
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
						Value: int32(helpers.SO_LOCK_FILTER.Value()),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "int",
						},
						Value: int32(helpers.SOL_IP.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: helpers.SO_LOCK_FILTER.String(),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "string",
						},
						Value: helpers.SOL_IP.String(),
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
						Value: int32(helpers.SO_ATTACH_FILTER.Value()),
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
						Value: int32(helpers.SO_LOCK_FILTER.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: helpers.SO_LOCK_FILTER.String(),
					},
				},
			},
		}

		for _, testCase := range testCases {
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
		}
	})

	t.Run("Parse getsockopt value", func(t *testing.T) {
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
						Value: int32(helpers.SO_LOCK_FILTER.Value()),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "int",
						},
						Value: int32(helpers.SOL_IP.Value()),
					},
				},
				expectedArgs: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "optname",
							Type: "string",
						},
						Value: helpers.SO_LOCK_FILTER.String(),
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "level",
							Type: "string",
						},
						Value: helpers.SOL_IP.String(),
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
						Value: int32(helpers.SO_GET_FILTER.Value()),
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
		}
	})
}
