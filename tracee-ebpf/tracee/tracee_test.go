package tracee

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadArgFromBuff(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedArg   interface{}
		expectedError error
	}{
		{
			name: "intT",
			input: []byte{1, //intT
				0,                      // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int32(-1),
		},
		{
			name: "uintT",
			input: []byte{2, //uintT
				0,                      // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "longT",
			input: []byte{3, //longT
				0,                                              // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int64(-1),
		},
		{
			name: "ulongT",
			input: []byte{4, //ulongT
				0,                                              // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "offT",
			input: []byte{5, //offT
				0,                                              // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "modeT",
			input: []byte{6, //modeT
				0,                    // Dummy tag
				0xB6, 0x11, 0x0, 0x0, //0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			expectedArg: uint32(0x11b6),
		},
		{
			name: "devT",
			input: []byte{7, //devT
				0,                      // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "offT",
			input: []byte{8, //offT
				0,                                              // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "pointerT",
			input: []byte{9, //pointerT
				0, // Dummy tag
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			expectedArg: uintptr(0xFFFFFFFFFFFFFFFF),
		},
		{
			name: "strT",
			input: []byte{10, //strT
				0,           // Dummy tag
				16, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			expectedArg: "/usr/bin/docker",
		},
		{
			name: "strArrT",
			input: []byte{11, // strArrT
				0,          // Dummy tag
				2,          //element number
				9, 0, 0, 0, //len=9
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				7, 0, 0, 0, //len=7
				100, 111, 99, 107, 101, 114, 0, //docker
			},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "sockAddrT - AF_INET",
			input: []byte{12, //sockAddrT
				0,    // Dummy tag
				2, 0, //sa_family=AF_INET
				0xFF, 0xFF, //sin_port=65535
				0xFF, 0xFF, 0xFF, 0xFF, //sin_addr=255.255.255.255
				0, 0, 0, 0, 0, 0, 0, 0, //padding[8]
			},
			expectedArg: map[string]string(map[string]string{"sa_family": "AF_INET", "sin_addr": "255.255.255.255", "sin_port": "65535"}),
		},
		{
			name: "sockAddrT - AF_UNIX",
			input: []byte{12, //sockAddrT
				0,    // Dummy tag
				1, 0, //sa_family=AF_UNIX
				47, 116, 109, 112, 47, 115, 111, 99, 107, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 101, 110, 0, 0, 0, // sun_path=/tmp/socket
			},
			expectedArg: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/tmp/socket"},
		},
		{
			name:          "unknown",
			input:         []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectedError: errors.New("error unknown arg type 222"),
		},
		{
			name: "strT too big",
			input: []byte{10, //strT
				0,          // Dummy tag
				0, 0, 0, 1, //len=16777216
			},
			expectedError: errors.New("string size too big: 16777216"),
		},
	}

	for _, tc := range testCases {
		b := bytes.NewReader(tc.input)
		_, actual, err := readArgFromBuff(b)
		assert.Equal(t, tc.expectedError, err, tc.name)
		assert.Equal(t, tc.expectedArg, actual, tc.name)

		if tc.name == "unknown" {
			continue
		} else {
			assert.Empty(t, b.Len(), tc.name) // passed in buffer should be emptied out
		}
	}
}
