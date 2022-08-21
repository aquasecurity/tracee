package ebpf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	dFd, err := os.Open(d)
	require.NoError(t, err)
	defer dFd.Close()

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
		outDir: dFd,
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
