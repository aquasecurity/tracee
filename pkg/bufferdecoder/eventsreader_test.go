package bufferdecoder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestReadArgFromBuff(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		input         []byte
		fields        []events.DataField
		expectedArg   interface{}
		expectedError error
	}{
		{
			name: "intT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // -1
			},
			fields:      []events.DataField{{DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Name: "int0"}}},
			expectedArg: int32(-1),
		},
		{
			name: "uintT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // 4294967295
			},
			fields:      []events.DataField{{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Name: "uint0"}}},
			expectedArg: uint32(4294967295),
		},
		{
			name: "longT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // -1
			},
			fields:      []events.DataField{{DecodeAs: data.LONG_T, ArgMeta: trace.ArgMeta{Name: "long0"}}},
			expectedArg: int64(-1),
		},
		{
			name: "ulongT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			fields:      []events.DataField{{DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Name: "ulong0"}}},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "modeT",
			input: []byte{0,
				0xB6, 0x11, 0x0, 0x0, // 0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			fields:      []events.DataField{{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Name: "modeT0"}}},
			expectedArg: uint32(0x11b6),
		},
		{
			name: "devT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // 4294967295
			},
			fields:      []events.DataField{{DecodeAs: data.UINT_T, ArgMeta: trace.ArgMeta{Name: "devT0"}}},
			expectedArg: uint32(4294967295),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "pointerT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			fields:      []events.DataField{{DecodeAs: data.POINTER_T, ArgMeta: trace.ArgMeta{Name: "pointer0"}}},
			expectedArg: trace.Pointer(0xFFFFFFFFFFFFFFFF),
		},
		{
			name: "strT",
			input: []byte{0,
				16, 0, 0, 0, // len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			fields:      []events.DataField{{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Name: "str0"}}},
			expectedArg: "/usr/bin/docker",
		},
		{
			name: "strArrT",
			input: []byte{0,
				2,          // element number
				9, 0, 0, 0, // len=9
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				7, 0, 0, 0, // len=7
				100, 111, 99, 107, 101, 114, 0, // docker
			},
			fields:      []events.DataField{{DecodeAs: data.STR_ARR_T, ArgMeta: trace.ArgMeta{Name: "strArr0"}}},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "argsArrT",
			input: []byte{0,
				16, 0, 0, 0, // array len
				2, 0, 0, 0, // number of arguments
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				100, 111, 99, 107, 101, 114, 0, // docker
			},
			fields:      []events.DataField{{DecodeAs: data.ARGS_ARR_T, ArgMeta: trace.ArgMeta{Name: "argsArr0"}}},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "sockAddrT - AF_INET",
			input: []byte{0,
				2, 0, // sa_family=AF_INET
				0xFF, 0xFF, // sin_port=65535
				0xFF, 0xFF, 0xFF, 0xFF, // sin_addr=255.255.255.255
				0, 0, 0, 0, 0, 0, 0, 0, // padding[8]
			},
			fields:      []events.DataField{{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Name: "sockAddr0"}}},
			expectedArg: map[string]string(map[string]string{"sa_family": "AF_INET", "sin_addr": "255.255.255.255", "sin_port": "65535"}),
		},
		{
			name: "sockAddrT - AF_UNIX",
			input: []byte{0,
				1, 0, // sa_family=AF_UNIX
				47, 116, 109, 112, 47, 115, 111, 99, 107, 101, 116, 0, // sun_path=/tmp/socket
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 101, 110, 0, 0, 0,
			},
			fields:      []events.DataField{{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Name: "sockAddr0"}}},
			expectedArg: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/tmp/socket"},
		},
		{
			name: "sockAddrT - AF_UNIX (abstract socket)",
			input: []byte{0,
				1, 0, // sa_family=AF_UNIX
				// it must be 108 bytes long
				0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 0, // sun_path=@something
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			fields:      []events.DataField{{DecodeAs: data.SOCK_ADDR_T, ArgMeta: trace.ArgMeta{Name: "sockAddr0"}}},
			expectedArg: map[string]string{"sa_family": "AF_UNIX", "sun_path": "@something"},
		},
		{
			name:          "unknown",
			input:         []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectedError: errors.New("invalid arg index 222"),
		},
		{
			name: "strT too big",
			input: []byte{0,
				0, 0, 0, 1, // len=16777216
			},
			fields:        []events.DataField{{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Name: "str0"}}},
			expectedError: errors.New("string size too big: 16777216"),
		},
		{
			name: "multiple fields",
			input: []byte{1,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			fields:      []events.DataField{{DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Name: "str0"}}, {DecodeAs: data.ULONG_T, ArgMeta: trace.ArgMeta{Name: "offT1"}}},
			expectedArg: uint64(18446744073709551615),
		},
	}

	dataPresentor := NewTypeDecoder()

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decoder := New(tc.input, dataPresentor)
			_, actual, err := readArgFromBuff(0, decoder, tc.fields)

			if err != nil {
				if tc.expectedError != nil {
					assert.ErrorContains(t, err, tc.expectedError.Error())
				} else {
					t.Logf("Encounted unexpected error: %v", err)
				}
			}
			assert.Equal(t, tc.expectedArg, actual.Value)

			if tc.name == "unknown" {
				return
			}
			assert.Empty(t, decoder.BuffLen()-decoder.BytesRead(), tc.name) // passed in buffer should be emptied out
		})
	}
}

func Test_readSunPathFromBuff(t *testing.T) {
	tests := []struct {
		name           string
		buffer         []byte
		max            int
		expected       string
		expectedCursor int
		expectError    bool
	}{
		{
			name:           "Null terminated string in larger buffer",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o', 0, 'W', 'o', 'r', 'l', 'd'},
			max:            6,
			expected:       "Hello",
			expectedCursor: 6,
			expectError:    false,
		},
		{
			name:           "Buffer with same length as max without null terminator",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o'},
			max:            5,
			expected:       "Hello",
			expectedCursor: 5,
			expectError:    false,
		},
		{
			name:           "Buffer longer than max length without null terminator",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o', 'W', 'o', 'r', 'l', 'd'},
			max:            5,
			expected:       "Hello",
			expectedCursor: 5,
			expectError:    false,
		},
		{
			name:           "Zero max length",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o', 0, 'W', 'o', 'r', 'l', 'd'},
			max:            0,
			expected:       "",
			expectedCursor: 0,
			expectError:    true,
		},
		{
			name:           "Buffer started with null terminator",
			buffer:         []byte{0, 'A', 'b', 's', 't', 'r', 'a', 'c', 't', 0, 'd'},
			max:            10,
			expected:       "@Abstract",
			expectedCursor: 10,
			expectError:    false,
		},
		{
			name:           "Zeroed buffer",
			buffer:         []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			max:            10,
			expected:       "",
			expectedCursor: 10,
			expectError:    false,
		},
		{
			name:           "Empty buffer",
			buffer:         []byte{},
			max:            5,
			expected:       "",
			expectedCursor: 0,
			expectError:    true,
		},
		{
			name:           "Buffer too short",
			buffer:         []byte{'H'},
			max:            5,
			expected:       "H",
			expectedCursor: 0,
			expectError:    true,
		},
	}

	dataPresentor := NewTypeDecoder()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := New(tt.buffer, dataPresentor)
			actual, err := readSunPathFromBuff(decoder, tt.max)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
				assert.Equal(t, tt.expectedCursor, decoder.BytesRead())
			}
		})
	}
}

func TestPrintUint32IP(t *testing.T) {
	t.Parallel()

	var input uint32 = 3232238339
	ip := PrintUint32IP(input)

	expectedIP := "192.168.11.3"
	assert.Equal(t, expectedIP, ip)
}

func TestPrint16BytesSliceIP(t *testing.T) {
	t.Parallel()

	input := []byte{32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52}
	ip := Print16BytesSliceIP(input)

	expectedIP := "2001:db8:85a3::8a2e:370:7334"
	assert.Equal(t, expectedIP, ip)
}
