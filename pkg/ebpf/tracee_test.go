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

	captureFileID := "host/exec.ls:123456789"

	// first run
	trc.updateProfile(captureFileID, 1, []string{"x", "y"}, []string{"FOO=bar"})

	require.Equal(t, profilerInfo{
		FirstExecutionTs: 1,
		Execution: []profilerExecution{
			{
				Args: []string{"x", "y"},
				Env:  []string{"FOO=bar"},
			},
		},
	}, trc.profiledFiles[captureFileID])

	// second run same bin
	trc.updateProfile(captureFileID, 2, []string{"xx", "yy"}, []string{"FOO=baz"})

	require.Equal(t, profilerInfo{
		FirstExecutionTs: 1,
		Execution: []profilerExecution{
			{
				Args: []string{"x", "y"},
				Env:  []string{"FOO=bar"},
			},
			{
				Args: []string{"xx", "yy"},
				Env:  []string{"FOO=baz"},
			},
		},
	}, trc.profiledFiles[captureFileID])

	// third run different bin
	trc.updateProfile(captureFileID+"123", 3, []string{"x", "y"}, []string{"FOO=bar"})

	require.Equal(t, profilerInfo{
		FirstExecutionTs: 1,
		Execution: []profilerExecution{
			{
				Args: []string{"x", "y"},
				Env:  []string{"FOO=bar"},
			},
			{
				Args: []string{"xx", "yy"},
				Env:  []string{"FOO=baz"},
			},
		},
	}, trc.profiledFiles[captureFileID])

	require.Equal(t, profilerInfo{
		FirstExecutionTs: 3,
		Execution: []profilerExecution{
			{
				Args: []string{"x", "y"},
				Env:  []string{"FOO=bar"},
			},
		},
	}, trc.profiledFiles[captureFileID+"123"])

	// should only create one entry
	require.Equal(t, 1, len(trc.profiledFiles))
}

func Test_writeProfilerStats(t *testing.T) {
	trc := Tracee{
		profiledFiles: map[string]profilerInfo{
			"bar": {
				FileHash: "4567",
				Execution: []profilerExecution{
					{
						Args: []string{"x", "y"},
						Env:  []string{"FOO=bar"},
					},
				},
			},
			"baz": {
				FileHash: "8901",
			},
			"foo": {
				FileHash: "1234",
			},
		},
	}

	var wr bytes.Buffer
	trc.writeProfilerStats(&wr)
	assert.JSONEq(t, `{
  "bar": {
    "file_hash": "4567",
		"execution": [
				{
					"args": ["x", "y"],
					"env":  ["FOO=bar"]
				}
		]
  },
  "baz": {
    "file_hash": "8901"
  },
  "foo": {
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
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Mmap), uint32(events.Mprotect), uint32(events.PkeyMprotect)}, ProgName: "sys_enter_init"},
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
