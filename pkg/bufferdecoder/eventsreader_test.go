package bufferdecoder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestReadArgFromBuff(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		input         []byte
		params        []trace.ArgMeta
		expectedArg   interface{}
		expectedError error
	}{
		{
			name: "intT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // -1
			},
			params:      []trace.ArgMeta{{Type: "int", Name: "int0"}},
			expectedArg: int32(-1),
		},
		{
			name: "uintT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // 4294967295
			},
			params:      []trace.ArgMeta{{Type: "unsigned int", Name: "uint0"}},
			expectedArg: uint32(4294967295),
		},
		{
			name: "longT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // -1
			},
			params:      []trace.ArgMeta{{Type: "long", Name: "long0"}},
			expectedArg: int64(-1),
		},
		{
			name: "ulongT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			params:      []trace.ArgMeta{{Type: "unsigned long", Name: "ulong0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "modeT",
			input: []byte{0,
				0xB6, 0x11, 0x0, 0x0, // 0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			params:      []trace.ArgMeta{{Type: "mode_t", Name: "modeT0"}},
			expectedArg: uint32(0x11b6),
		},
		{
			name: "devT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, // 4294967295
			},
			params:      []trace.ArgMeta{{Type: "dev_t", Name: "devT0"}},
			expectedArg: uint32(4294967295),
		},
		{
			name: "offT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			params:      []trace.ArgMeta{{Type: "off_t", Name: "offT0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "loffT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			params:      []trace.ArgMeta{{Type: "loff_t", Name: "loffT0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "pointerT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			params:      []trace.ArgMeta{{Type: "void*", Name: "pointer0"}},
			expectedArg: uintptr(0xFFFFFFFFFFFFFFFF),
		},
		{
			name: "strT",
			input: []byte{0,
				16, 0, 0, 0, // len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			params:      []trace.ArgMeta{{Type: "const char*", Name: "str0"}},
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
			params:      []trace.ArgMeta{{Type: "const char*const*", Name: "strArr0"}},
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
			params:      []trace.ArgMeta{{Type: "const char**", Name: "argsArr0"}},
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
			params:      []trace.ArgMeta{{Type: "struct sockaddr*", Name: "sockAddr0"}},
			expectedArg: map[string]string(map[string]string{"sa_family": "AF_INET", "sin_addr": "255.255.255.255", "sin_port": "65535"}),
		},
		{
			name: "sockAddrT - AF_UNIX",
			input: []byte{0,
				1, 0, // sa_family=AF_UNIX
				47, 116, 109, 112, 47, 115, 111, 99, 107, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 101, 110, 0, 0, 0, // sun_path=/tmp/socket
			},
			params:      []trace.ArgMeta{{Type: "struct sockaddr*", Name: "sockAddr0"}},
			expectedArg: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/tmp/socket"},
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
			params:        []trace.ArgMeta{{Type: "const char*", Name: "str0"}},
			expectedError: errors.New("string size too big: 16777216"),
		},
		{
			name: "multiple params",
			input: []byte{1,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 18446744073709551615
			},
			params:      []trace.ArgMeta{{Type: "const char*", Name: "str0"}, {Type: "off_t", Name: "offT1"}},
			expectedArg: uint64(18446744073709551615),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decoder := New(tc.input)
			_, actual, err := readArgFromBuff(0, decoder, tc.params)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			}
			assert.Equal(t, tc.expectedArg, actual.Value)

			if tc.name == "unknown" {
				return
			}
			assert.Empty(t, decoder.BuffLen()-decoder.ReadAmountBytes(), tc.name) // passed in buffer should be emptied out
		})
	}
}

func TestReadStringVarFromBuff(t *testing.T) {
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
			expected:       "Hell",
			expectedCursor: 5,
			expectError:    false,
		},
		{
			name:           "Buffer longer than max length without null terminator",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o', 'W', 'o', 'r', 'l', 'd'},
			max:            5,
			expected:       "Hell",
			expectedCursor: 5,
			expectError:    false,
		},
		{
			name:           "Zero max length",
			buffer:         []byte{'H', 'e', 'l', 'l', 'o', 0, 'W', 'o', 'r', 'l', 'd'},
			max:            0,
			expected:       "",
			expectedCursor: 0,
			expectError:    false,
		},
		{
			name:           "Buffer started with null terminator",
			buffer:         []byte{0, 'N', 'u', 'l', 'l', 0, 'W', 'o', 'r', 'l', 'd'},
			max:            6,
			expected:       "",
			expectedCursor: 6,
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := New(tt.buffer)
			actual, err := readStringVarFromBuff(decoder, tt.max)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
				assert.Equal(t, tt.expectedCursor, decoder.ReadAmountBytes())
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
