package parse

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestArgVal(t *testing.T) {
	t.Parallel()

	t.Run("int32", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue int32
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "int",
					},
					Value: int32(1878),
				},
				expectedValue: int32(1878),
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: int64(1878),
				},
				errorMessage: "argument invalid_val is not of type int32",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "int",
					},
					Value: int32(1878),
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[int32](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue string
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "string",
					},
					Value: "hello_tracee",
				},
				expectedValue: "hello_tracee",
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: int64(1878),
				},
				errorMessage: "argument invalid_val is not of type string",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "string",
					},
					Value: "hola_tracee",
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[string](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})

	t.Run("uint64", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue uint64
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "int",
					},
					Value: uint64(1878),
				},
				expectedValue: uint64(1878),
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: uint32(1878),
				},
				errorMessage: "argument invalid_val is not of type uint64",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "int",
					},
					Value: uint64(1878),
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[uint64](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})

	t.Run("uint32", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue uint32
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "int",
					},
					Value: uint32(1878),
				},
				expectedValue: uint32(1878),
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: uint64(1878),
				},
				errorMessage: "argument invalid_val is not of type uint32",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "int",
					},
					Value: uint32(1878),
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[uint32](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})

	t.Run("[]string", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue []string
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "string",
					},
					Value: []string{"hello", "tracee", "ebpf"},
				},
				expectedValue: []string{"hello", "tracee", "ebpf"},
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: int64(1878),
				},
				errorMessage: "argument invalid_val is not of type []string",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "string",
					},
					Value: []string{"hello", "tracee", "ebpf"},
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[[]string](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})

	t.Run("[]uint64", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name          string
			arg           trace.Argument
			expectedValue []uint64
			errorMessage  string
		}{
			{
				name: "valid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "valid_val",
						Type: "int",
					},
					Value: []uint64{1878, 1878, 1878},
				},
				expectedValue: []uint64{1878, 1878, 1878},
			},
			{
				name: "invalid_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "invalid_val",
						Type: "int",
					},
					Value: []uint32{1878, 1878, 1878},
				},
				errorMessage: "argument invalid_val is not of type []uint64",
			},
			{
				name: "no_val",
				arg: trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "does_not_exist_val",
						Type: "int",
					},
					Value: []uint64{1878, 1878, 1878},
				},
				errorMessage: "argument no_val not found",
			},
		}

		for _, tt := range tests {
			tt := tt

			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				e := trace.Event{Args: []trace.Argument{tt.arg}}
				val, err := ArgVal[[]uint64](e.Args, tt.name)
				if tt.errorMessage != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errorMessage)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedValue, val)
				}
			})
		}
	})
}
