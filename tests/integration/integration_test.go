package integration

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// small set of actions to trigger a magic write event
func checkMagicwrite(t *testing.T, gotOutput *[]trace.Event) {
	// create a temp dir for testing
	d, err := ioutil.TempDir("", "Test_MagicWrite-dir-*")
	require.NoError(t, err)

	// cp a file to trigger
	f, err := os.CreateTemp(d, "Test_MagicWrite-file-*")
	require.NoError(t, err)
	defer func() {
		os.Remove(d)
	}()

	f.WriteString(`foo.bar.baz`)
	f.Close()

	cpCmd := exec.Command("cp", f.Name(), filepath.Join(d+filepath.Base(f.Name())+"-new"))
	fmt.Println("executing: ", cpCmd.String())
	cpCmd.Stdout = os.Stdout
	assert.NoError(t, cpCmd.Run())

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check tracee output
	expect := []byte{102, 111, 111, 46, 98, 97, 114, 46, 98, 97, 122}
	fail := true
	for _, evt := range *gotOutput {
		arg := events.GetArg(&evt, "bytes")
		argVal, ok := arg.Value.([]byte)
		require.Equal(t, true, ok)
		ok = assert.ElementsMatch(t, argVal, expect)
		if ok {
			fail = false
		}
	}
	if fail {
		t.Fail()
	}
}

// execute a ls command
func checkExeccommand(t *testing.T, gotOutput *[]trace.Event) {
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check tracee output
	processNames := []string{}
	for _, evt := range *gotOutput {
		processNames = append(processNames, evt.ProcessName)
	}
	for _, pname := range processNames {
		assert.Equal(t, "ls", pname)
	}
}

// only capture new pids after tracee
func checkPidnew(t *testing.T, gotOutput *[]trace.Event) {
	traceePid := os.Getpid()

	// run a command
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// output should only have events with pids greater (newer) than tracee
	pids := []int{}
	for _, evt := range *gotOutput {
		if evt.ProcessName == "ls" {
			pids = append(pids, evt.ProcessID)
		}
	}
	for _, pid := range pids {
		assert.Greater(t, pid, traceePid)
	}
}

// only capture uids of 0 that are run by comm ls
func checkUidZero(t *testing.T, gotOutput *[]trace.Event) {
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	// output should only have events with uids of 0
	uids := []int{}
	for _, evt := range *gotOutput {
		uids = append(uids, evt.UserID)
	}
	for _, uid := range uids {
		require.Zero(t, uid)
	}
}

// trigger ls from uid 0 (tests run as root) and check if empty
func checkUidNonZero(t *testing.T, gotOutput *[]trace.Event) {
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), false)

	// check output length
	assert.Empty(t, gotOutput)
}

// check that execve event is called
func checkExecve(t *testing.T, gotOutput *[]trace.Event) {
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	// output should only have events with event name of execve
	eventNames := []string{}
	for _, evt := range *gotOutput {
		eventNames = append(eventNames, evt.EventName)
	}
	for _, en := range eventNames {
		if len(en) > 0 {
			require.Equal(t, "execve", en)
		}
	}
}

// check for filesystem set when ls is invoked
func checkSetFs(t *testing.T, gotOutput *[]trace.Event) {
	err := exec.Command("ls").Run()
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	expectedSyscalls := getAllSyscallsInSet("fs")

	// output should only have events with events in the set of filesystem syscalls
	eventNames := []string{}
	for _, evt := range *gotOutput {
		eventNames = append(eventNames, evt.EventName)
	}
	for _, en := range eventNames {
		require.Contains(t, expectedSyscalls, en)
	}
}

func getAllSyscallsInSet(set string) []string {
	var syscallsInSet []string
	for _, v := range events.Definitions.Events() {
		for _, c := range v.Sets {
			if c == set {
				syscallsInSet = append(syscallsInSet, v.Name)
			}
		}
	}
	return syscallsInSet
}
func Test_EventFilters(t *testing.T) {
	testCases := []struct {
		name       string
		filterArgs []string
		eventFunc  func(*testing.T, *[]trace.Event)
	}{
		{
			name:       "do a file write",
			filterArgs: []string{"event=magic_write"},
			eventFunc:  checkMagicwrite,
		},
		{
			name:       "execute a command",
			filterArgs: []string{"comm=ls"},
			eventFunc:  checkExeccommand,
		},
		{
			name:       "trace new pids",
			filterArgs: []string{"pid=new"},
			eventFunc:  checkPidnew,
		},
		{
			name:       "trace uid 0 with comm ls",
			filterArgs: []string{"uid=0", "comm=ls"},
			eventFunc:  checkUidZero,
		},
		{
			name:       "trace only ls comms from uid>0 (should be empty)",
			filterArgs: []string{"uid>0", "comm=ls"},
			eventFunc:  checkUidNonZero,
		},
		//TODO: Add pid=0,1
		//TODO: Add pid=0 pid=1
		//TODO: Add uid>0
		//TODO: Add pid>0 pid<1000
		//TODO: Add u>0 u!=1000
		{
			name:       "trace filesystem events from comm ls",
			filterArgs: []string{"s=fs", "comm=ls"},
			eventFunc:  checkSetFs,
		},
		{
			name:       "trace only execve events from comm ls",
			filterArgs: []string{"event=execve", "execve.pathname=*ls"},
			eventFunc:  checkExecve,
		},
		{
			name:       "trace only execve events that starts with /usr/bin",
			filterArgs: []string{"event=execve", "execve.pathname=/usr/bin*"},
			eventFunc:  checkExecve,
		},
		{
			name:       "trace only execve events that contains l",
			filterArgs: []string{"event=execve", "execve.pathname=*l*"},
			eventFunc:  checkExecve,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			filter, err := flags.PrepareFilter(tc.filterArgs)
			require.NoError(t, err)

			eventChan := make(chan trace.Event, 1000)
			config := tracee.Config{
				Filter:     &filter,
				ChanEvents: eventChan,
			}
			eventOutput := []trace.Event{}

			go func() {
				for evt := range eventChan {
					eventOutput = append(eventOutput, evt)
				}
			}()

			trc := startTracee(t, config, nil, nil, ctx)

			waitforTraceeStart(t, trc, time.Now())

			tc.eventFunc(t, &eventOutput)
			cancel()
		})
	}
}
