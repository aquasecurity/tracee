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
			name: "INT_T",
			input: []byte{1, //INT_T
				0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int32(-1),
		},
		{
			name: "UINT_T",
			input: []byte{2, //UINT_T
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "LONG_T",
			input: []byte{3, //LONG_T
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			expectedArg: int64(-1),
		},
		{
			name: "ULONG_T",
			input: []byte{4, //ULONG_T
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "OFF_T_T",
			input: []byte{5, //OFF_T_T
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "MODE_T_T",
			input: []byte{6, //MODE_T_T
				0xB6, 0x11, 0x0, 0x0, //0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			expectedArg: "S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH",
		},
		{
			name: "DEV_T_T",
			input: []byte{7, //DEV_T_T
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			expectedArg: uint32(4294967295),
		},
		{
			name: "OFF_T_T",
			input: []byte{8, //OFF_T_T
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			expectedArg: uint64(18446744073709551615),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "POINTER_T",
			input: []byte{9, //POINTER_T
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			expectedArg: "0xFFFFFFFFFFFFFFFF",
		},
		{
			name: "STR_T",
			input: []byte{10, //STR_T
				16, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			expectedArg: "/usr/bin/docker",
		},
		{
			name: "STR_ARR_T",
			input: []byte{11, // STR_ARR_T
				10,         //STR_T
				9, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				10,         //STR_T
				7, 0, 0, 0, //len=7
				100, 111, 99, 107, 101, 114, 0, //docker
				11, // end STR_ARR_T
			},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "SOCKADDR_T",
			input: []byte{12, //SOCKADDR_T
				2, 0, //sa_family=AF_INET
				0xFF, 0xFF, //sin_port=65535
				0xFF, 0xFF, 0xFF, 0xFF, //sin_addr=255.255.255.255
			},
			expectedArg: "[sa_family:AF_INET sin_addr:255.255.255.255 sin_port:65535]",
		},
		{
			name: "OPEN_FLAGS_T",
			input: []byte{13, //OPEN_FLAGS_T
				0x82, 0x24, 0x49, 0x0, //CAP_NET_BIND_SERVICE
			},
			expectedArg: "O_RDWR|O_EXCL|O_APPEND|O_ASYNC|O_DIRECTORY|O_CLOEXEC|O_TMPFILE",
		},
		{
			name: "EXEC_FLAGS_T",
			input: []byte{14, //EXEC_FLAGS_T
				0x0, 0x11, 0x0, 0x0, //AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW
			},
			expectedArg: "AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW",
		},
		{
			name: "SOCK_DOM_T",
			input: []byte{15, //SOCK_DOM_T
				2, 0, 0, 0, //AF_INET
			},
			expectedArg: "AF_INET",
		},
		{
			name: "SOCK_TYPE_T",
			input: []byte{16, //SOCK_TYPE_T
				0x3, 0x8, 0x8, 0x0, //SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC
			},
			expectedArg: "SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC",
		},
		{
			name: "CAP_T",
			input: []byte{17, //CAP_T
				10, 0, 0, 0, //CAP_NET_BIND_SERVICE
			},
			expectedArg: "CAP_NET_BIND_SERVICE",
		},
		{
			name: "SYSCALL_T",
			input: []byte{18, //SYSCALL_T
				25, 0, 0, 0, //mremap
			},
			expectedArg: "mremap",
		},
		{
			name: "PROT_FLAGS_T",
			input: []byte{19, //PROT_FLAGS_T
				0x7, 0x0, 0x0, 0x0, //PROT_READ|PROT_WRITE|PROT_EXEC
			},
			expectedArg: "PROT_READ|PROT_WRITE|PROT_EXEC",
		},
		{
			name: "ACCESS_MODE_T",
			input: []byte{20, //ACCESS_MODE_T
				0x7, 0x0, 0x0, 0x0, //R_OK|W_OK|X_OK
			},
			expectedArg: "R_OK|W_OK|X_OK",
		},
		{
			name: "PTRACE_REQ_T",
			input: []byte{21, //PTRACE_REQ_T
				0x10, 0x0, 0x0, 0x0, //PTRACE_ATTACH
			},
			expectedArg: "PTRACE_ATTACH",
		},
		{
			name: "PRCTL_OPT_T",
			input: []byte{22, //PRCTL_OPT_T
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
