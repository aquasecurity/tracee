package ebpf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
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

func Test_getTailCalls(t *testing.T) {
	testCases := []struct {
		name              string
		events            map[events.ID]eventConfig
		expectedTailCalls []events.TailCall
		expectedErr       error
	}{
		{
			name: "happy path - some direct syscalls and syscall requiring events",
			events: map[events.ID]eventConfig{
				events.Ptrace:           {submit: true, emit: true},
				events.ClockSettime:     {submit: true, emit: true},
				events.SecurityFileOpen: {submit: true, emit: true},
				events.MemProtAlert:     {submit: true, emit: true},
				events.SocketDup:        {submit: true, emit: true},
			},
			expectedTailCalls: []events.TailCall{
				{MapName: "sys_exit_tails", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_dup_exit_tail"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_enter_init"},
				{MapName: "sys_exit_init_tail", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_exit_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{
					uint32(events.Open), uint32(events.Openat), uint32(events.Openat2), uint32(events.OpenByHandleAt),
					uint32(events.Execve), uint32(events.Execveat),
				}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Mmap), uint32(events.Mprotect)}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_submit_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_enter_submit"},
				{MapName: "sys_exit_init_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_exit_init"},
				{MapName: "sys_exit_submit_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_exit_submit"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tailCalls, err := getTailCalls(tc.events)
			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				for n := range tailCalls {
					sort.Slice(tailCalls[n].MapIndexes, func(i, j int) bool {
						return tailCalls[n].MapIndexes[i] < tailCalls[n].MapIndexes[j]
					})
				}
				for n := range tc.expectedTailCalls {
					sort.Slice(tc.expectedTailCalls[n].MapIndexes, func(i, j int) bool {
						return tc.expectedTailCalls[n].MapIndexes[i] < tc.expectedTailCalls[n].MapIndexes[j]
					})
				}
				assert.ElementsMatch(t, tailCalls, tc.expectedTailCalls)
			}
		})
	}
}
