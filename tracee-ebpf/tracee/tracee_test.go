package tracee

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadArgFromBuff(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		params        []external.ArgMeta
		expectedArg   interface{}
		expectedError error
	}{
		{
			name: "intT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			params:      []external.ArgMeta{{Type: "int", Name: "int0"}},
			expectedArg: int32(-1),
		},
		{
			name: "uintT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			params:      []external.ArgMeta{{Type: "unsigned int", Name: "uint0"}},
			expectedArg: uint32(4294967295),
		},
		{
			name: "longT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //-1
			},
			params:      []external.ArgMeta{{Type: "long", Name: "long0"}},
			expectedArg: int64(-1),
		},
		{
			name: "ulongT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			params:      []external.ArgMeta{{Type: "unsigned long", Name: "ulong0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "offT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			params:      []external.ArgMeta{{Type: "off_t", Name: "offT0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{
			name: "modeT",
			input: []byte{0,
				0xB6, 0x11, 0x0, 0x0, //0x000011B6 == 010666 == S_IFIFO|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
			},
			params:      []external.ArgMeta{{Type: "mode_t", Name: "modeT0"}},
			expectedArg: uint32(0x11b6),
		},
		{
			name: "devT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, //4294967295
			},
			params:      []external.ArgMeta{{Type: "dev_t", Name: "devT0"}},
			expectedArg: uint32(4294967295),
		},
		{
			name: "offT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			params:      []external.ArgMeta{{Type: "off_t", Name: "offT0"}},
			expectedArg: uint64(18446744073709551615),
		},
		{ // This is expected to fail. TODO: change pointer parsed type to uint64
			name: "pointerT",
			input: []byte{0,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			params:      []external.ArgMeta{{Type: "void*", Name: "pointer0"}},
			expectedArg: uintptr(0xFFFFFFFFFFFFFFFF),
		},
		{
			name: "strT",
			input: []byte{0,
				16, 0, 0, 0, //len=16
				47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114, 0, // /usr/bin/docker
			},
			params:      []external.ArgMeta{{Type: "const char*", Name: "str0"}},
			expectedArg: "/usr/bin/docker",
		},
		{
			name: "strArrT",
			input: []byte{0,
				2,          //element number
				9, 0, 0, 0, //len=9
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				7, 0, 0, 0, //len=7
				100, 111, 99, 107, 101, 114, 0, //docker
			},
			params:      []external.ArgMeta{{Type: "const char*const*", Name: "strArr0"}},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "argsArrT",
			input: []byte{0,
				16, 0, 0, 0, //array len
				2, 0, 0, 0, //number of arguments
				47, 117, 115, 114, 47, 98, 105, 110, 0, // /usr/bin
				100, 111, 99, 107, 101, 114, 0, //docker
			},
			params:      []external.ArgMeta{{Type: "const char**", Name: "argsArr0"}},
			expectedArg: []string{"/usr/bin", "docker"},
		},
		{
			name: "sockAddrT - AF_INET",
			input: []byte{0,
				2, 0, //sa_family=AF_INET
				0xFF, 0xFF, //sin_port=65535
				0xFF, 0xFF, 0xFF, 0xFF, //sin_addr=255.255.255.255
				0, 0, 0, 0, 0, 0, 0, 0, //padding[8]
			},
			params:      []external.ArgMeta{{Type: "struct sockaddr*", Name: "sockAddr0"}},
			expectedArg: map[string]string(map[string]string{"sa_family": "AF_INET", "sin_addr": "255.255.255.255", "sin_port": "65535"}),
		},
		{
			name: "sockAddrT - AF_UNIX",
			input: []byte{0,
				1, 0, //sa_family=AF_UNIX
				47, 116, 109, 112, 47, 115, 111, 99, 107, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 101, 110, 0, 0, 0, // sun_path=/tmp/socket
			},
			params:      []external.ArgMeta{{Type: "struct sockaddr*", Name: "sockAddr0"}},
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
				0, 0, 0, 1, //len=16777216
			},
			params:        []external.ArgMeta{{Type: "const char*", Name: "str0"}},
			expectedError: errors.New("string size too big: 16777216"),
		},
		{
			name: "multiple params",
			input: []byte{1,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //18446744073709551615
			},
			params:      []external.ArgMeta{{Type: "const char*", Name: "str0"}, {Type: "off_t", Name: "offT1"}},
			expectedArg: uint64(18446744073709551615),
		},
	}

	for _, tc := range testCases {
		b := bytes.NewReader(tc.input)
		_, actual, err := readArgFromBuff(b, tc.params)
		assert.Equal(t, tc.expectedError, err, tc.name)
		assert.Equal(t, tc.expectedArg, actual, tc.name)

		if tc.name == "unknown" {
			continue
		} else {
			assert.Empty(t, b.Len(), tc.name) // passed in buffer should be emptied out
		}
	}
}

func Test_updateProfile(t *testing.T) {
	trc := Tracee{
		profiledFiles: make(map[string]profilerInfo),
	}

	d, err := ioutil.TempDir("", "Test_updateProfile_dir-*")
	require.NoError(t, err)

	f, err := ioutil.TempFile(d, "Test_updateProfile-*")
	require.NoError(t, err)
	defer os.RemoveAll(f.Name())

	captureFileID := fmt.Sprintf("%s.%s", d, filepath.Base(f.Name()))

	// first run
	trc.updateProfile(captureFileID, 123)

	require.Equal(t, profilerInfo{
		Times:            1,
		FirstExecutionTs: 123,
	}, trc.profiledFiles[captureFileID])

	// second update run
	trc.updateProfile(captureFileID, 456)

	require.Equal(t, profilerInfo{
		Times:            2,   // should be execute twice
		FirstExecutionTs: 123, // first execution should remain constant
	}, trc.profiledFiles[captureFileID])

	// should only create one entry
	require.Equal(t, 1, len(trc.profiledFiles))
}

func Test_writeProfilerStats(t *testing.T) {
	trc := Tracee{
		profiledFiles: map[string]profilerInfo{
			"bar": {
				Times:    3,
				FileHash: "4567",
			},
			"baz": {
				Times:    5,
				FileHash: "8901",
			},
			"foo": {
				Times:    1,
				FileHash: "1234",
			},
		},
	}

	var wr bytes.Buffer
	trc.writeProfilerStats(&wr)
	assert.JSONEq(t, `{
  "bar": {
    "times": 3,
    "file_hash": "4567"
  },
  "baz": {
    "times": 5,
    "file_hash": "8901"
  },
  "foo": {
    "times": 1,
    "file_hash": "1234"
  }
}
`, wr.String())
}

func Test_updateFileSHA(t *testing.T) {
	d, err := ioutil.TempDir("", "Test_updateFileSHA-dir-*")
	require.NoError(t, err)

	ts := 456
	f, _ := ioutil.TempFile(d, fmt.Sprintf(".%d.Test_updateFileSHA-*", ts))
	f.WriteString("foo bar baz")
	defer func() {
		os.Remove(f.Name())
	}()

	trc := Tracee{
		profiledFiles: map[string]profilerInfo{
			fmt.Sprintf("%s/.%s:%d", d, strings.TrimPrefix(filepath.Base(f.Name()), fmt.Sprintf(".%d.", ts)), 1234): {
				Times:            123,
				FirstExecutionTs: 456,
				// no file sha
			},
		},
	}

	// file sha is updated
	trc.updateFileSHA()

	// check
	assert.Equal(t, map[string]profilerInfo{
		fmt.Sprintf("%s/.%s:1234", d, strings.TrimPrefix(filepath.Base(f.Name()), fmt.Sprintf(".%d.", ts))): {
			Times:            123,
			FirstExecutionTs: 456,
			FileHash:         "dbd318c1c462aee872f41109a4dfd3048871a03dedd0fe0e757ced57dad6f2d7",
		},
	}, trc.profiledFiles)
}
