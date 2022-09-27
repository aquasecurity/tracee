package parse

import (
	"testing"

	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
)

func TestArgInt32Val(t *testing.T) {

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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgInt32Val(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}
}

func TestArgStringVal(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgStringVal(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}

}

func TestArgUint64Val(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgUint64Val(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}

}

func TestArgUint32Val(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgUint32Val(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}

}

func TestArgStringArrVal(t *testing.T) {
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
			errorMessage: "argument invalid_val is not of type string",
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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgStringArrVal(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}
}

func TestArgUlongArrVal(t *testing.T) {
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
			errorMessage: "argument invalid_val is not of type ulong array",
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
		t.Run(tt.name, func(t *testing.T) {
			e := trace.Event{Args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: tt.arg.Name,
						Type: tt.arg.Type,
					},
					Value: tt.arg.Value,
				},
			}}
			val, err := ArgUlongArrVal(&e, tt.name)
			if tt.errorMessage != "" {
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Error(t, err)
			} else {
				assert.Equal(t, tt.expectedValue, val)
				assert.NoError(t, err)
			}
		})
	}
}
