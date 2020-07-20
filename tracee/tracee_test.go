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
				0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int32(-1),
		},
		{
			name: "uintT",
			input: []byte{2, //uintT
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "longT",
			input: []byte{3, //longT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int64(-1),
		},
		{
			name: "ulongT",
			input: []byte{4, //ulongT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "offT",
			input: []byte{5, //offT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "modeT",
			input: []byte{6, //modeT
				0xB6, 0x11, 0x0, 0x0, //0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			expectedArg: "S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH",
		},
		{
			name: "devT",
			input: []byte{7, //devT
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "offT",
			input: []byte{8, //offT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "pointerT",
			input: []byte{9, //pointerT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			expectedArg: "0xFFFFFFFFFFFFFFFF",
		},
		{
			name: "strT",
			input: []byte{10, //strT
				16, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			expectedArg: "/usr/bin/docker",
		},
		{
			name: "strArrT",
			input: []byte{11, // strArrT
				10,         //strT
				9, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				10,         //strT
				7, 0, 0, 0, //len=7
				100, 111, 99, 107, 101, 114, 0, //docker
				11, // end strArrT
			},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "sockAddrT",
			input: []byte{12, //sockAddrT
				2, 0, //sa_family=AF_INET
				0xFF, 0xFF, //sin_port=65535
				0xFF, 0xFF, 0xFF, 0xFF, //sin_addr=255.255.255.255
			},
			expectedArg: "{'sa_family': 'AF_INET','sin_port': '65535','sin_addr': '255.255.255.255'}",
		},
		{
			name: "openFlagsT",
			input: []byte{13, //openFlagsT
				0x82, 0x24, 0x49, 0x0, //CAP_NET_BIND_SERVICE
			},
			expectedArg: "O_RDWR|O_EXCL|O_APPEND|O_ASYNC|O_DIRECTORY|O_CLOEXEC|O_TMPFILE",
		},
		{
			name: "execFlagsT",
			input: []byte{14, //execFlagsT
				0x0, 0x11, 0x0, 0x0, //AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW
			},
			expectedArg: "AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW",
		},
		{
			name: "sockDomT",
			input: []byte{15, //sockDomT
				2, 0, 0, 0, //AF_INET
			},
			expectedArg: "AF_INET",
		},
		{
			name: "sockTypeT",
			input: []byte{16, //sockTypeT
				0x3, 0x8, 0x8, 0x0, //SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC
			},
			expectedArg: "SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC",
		},
		{
			name: "capT",
			input: []byte{17, //capT
				10, 0, 0, 0, //CAP_NET_BIND_SERVICE
			},
			expectedArg: "CAP_NET_BIND_SERVICE",
		},
		{
			name: "syscallT",
			input: []byte{18, //syscallT
				25, 0, 0, 0, //mremap
			},
			expectedArg: "mremap",
		},
		{
			name: "protFlagsT",
			input: []byte{19, //protFlagsT
				0x7, 0x0, 0x0, 0x0, //PROT_READ|PROT_WRITE|PROT_EXEC
			},
			expectedArg: "PROT_READ|PROT_WRITE|PROT_EXEC",
		},
		{
			name: "accessModeT",
			input: []byte{20, //accessModeT
				0x7, 0x0, 0x0, 0x0, //R_OK|W_OK|X_OK
			},
			expectedArg: "R_OK|W_OK|X_OK",
		},
		{
			name: "ptraceReqT",
			input: []byte{21, //ptraceReqT
				0x10, 0x0, 0x0, 0x0, //PTRACE_ATTACH
			},
			expectedArg: "PTRACE_ATTACH",
		},
		{
			name: "prctlOptT",
			input: []byte{22, //prctlOptT
				0x19, 0x0, 0x0, 0x0, //PR_GET_TSC
			},
			expectedArg: "PR_GET_TSC",
		},
		{
			name:          "unknown",
			input:         []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectedError: errors.New("error unknown arg type 222"),
		},
	}

	for _, tc := range testCases {
		actual, err := readArgFromBuff(bytes.NewReader(tc.input))
		assert.Equal(t, tc.expectedError, err, tc.name)
		assert.Equal(t, tc.expectedArg, actual, tc.name)
	}
}
