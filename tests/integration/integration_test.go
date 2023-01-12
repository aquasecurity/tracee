package integration

import (
	"context"
	_ "embed"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// small set of actions to trigger a magic write event
func checkMagicwrite(t *testing.T, gotOutput *[]trace.Event) {

	_, err := forkAndExecFunction(doMagicWrite)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check tracee output
	for _, evt := range *gotOutput {
		assert.Equal(t, []byte(evt.EventName), []byte("magic_write"))
	}
}

// execute a ls command
func checkExeccommand(t *testing.T, gotOutput *[]trace.Event) {
	_, err := forkAndExecFunction(doLs)
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

	_, err := forkAndExecFunction(doLs)
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
	_, err := forkAndExecFunction(doLs)
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
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), false)

	// check output length
	assert.Empty(t, gotOutput)
}

// check that execve event is called
func checkExecve(t *testing.T, gotOutput *[]trace.Event) {
	_, err := forkAndExecFunction(doLs)
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
	_, err := forkAndExecFunction(doLs)
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

func checkNewContainers(t *testing.T, gotOutput *[]trace.Event) {
	containerIdBytes, err := forkAndExecFunction(doDockerRun)
	require.NoError(t, err)
	containerId := strings.TrimSuffix(string(containerIdBytes), "\n")
	containerIds := []string{}
	for _, evt := range *gotOutput {
		containerIds = append(containerIds, evt.ContainerID)
	}
	for _, id := range containerIds {
		assert.Equal(t, containerId, id)
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

func checkSecurityFileOpenExecve(t *testing.T, gotOutput *[]trace.Event) {
	_, err := forkAndExecFunction(doFileOpen)
	require.NoError(t, err)

	syscallArgs := []events.ID{}
	for _, evt := range *gotOutput {
		arg, err := helpers.GetTraceeArgumentByName(evt, "syscall")
		require.NoError(t, err)
		syscallArgs = append(syscallArgs, events.ID(arg.Value.(int32)))
	}
	for _, syscall := range syscallArgs {
		assert.Equal(t, events.Execve, syscall)
	}
}

func checkScope42SecurityFileOpenLs(t *testing.T, gotOutput *[]trace.Event) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	for _, evt := range *gotOutput {
		// ls - scope 42
		assert.Equal(t, "ls", evt.ProcessName)
		assert.Equal(t, uint64(1<<41), evt.MatchedScopes)
		arg, err := helpers.GetTraceeArgumentByName(evt, "pathname")
		require.NoError(t, err)
		assert.Contains(t, arg.Value, "integration")
	}
}

func checkExecveOnScopes4And2(t *testing.T, gotOutput *[]trace.Event) {
	_, err := forkAndExecFunction(doLsUname)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.Len(t, *gotOutput, 2)
	var evts [2]trace.Event

	// output should only have events with event name of execve
	for i, evt := range *gotOutput {
		assert.Equal(t, "execve", evt.EventName)
		evts[i] = evt
	}

	// ls - scope 4
	arg, err := helpers.GetTraceeArgumentByName(evts[0], "pathname")
	require.NoError(t, err)
	assert.Contains(t, arg.Value, "ls")
	assert.Equal(t, uint64(1<<3), evts[0].MatchedScopes, "MatchedScopes")

	// uname - scope 2
	arg, err = helpers.GetTraceeArgumentByName(evts[1], "pathname")
	require.NoError(t, err)
	assert.Contains(t, arg.Value, "uname")
	assert.Equal(t, uint64(1<<1), evts[1].MatchedScopes, "MatchedScopes")
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
			filterArgs: []string{"event=execve", "execve.args.pathname=*ls"},
			eventFunc:  checkExecve,
		},
		{
			name:       "trace only execve events that starts with /usr/bin",
			filterArgs: []string{"event=execve", "execve.args.pathname=/usr/bin*"},
			eventFunc:  checkExecve,
		},
		{
			name:       "trace only execve events that contains l",
			filterArgs: []string{"event=execve", "execve.args.pathname=*l*"},
			eventFunc:  checkExecve,
		},
		{
			name:       "trace only events from new containers",
			filterArgs: []string{"container=new"},
			eventFunc:  checkNewContainers,
		},
		{
			name:       "trace event set in a specific scope",
			filterArgs: []string{"42:comm=ls", "42:event=security_file_open", "42:security_file_open.args.pathname=*integration"},
			eventFunc:  checkScope42SecurityFileOpenLs,
		},
		{
			name: "trace events set in two specific scope",
			filterArgs: []string{
				"4:event=execve", "4:execve.args.pathname=*ls",
				"2:event=execve", "2:execve.args.pathname=*uname",
			},
			eventFunc: checkExecveOnScopes4And2,
		},
		{
			name:       "trace only security_file_open from \"execve\" syscall",
			filterArgs: []string{"event=security_file_open", "security_file_open.args.syscall=execve"},
			eventFunc:  checkSecurityFileOpenExecve,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			filterScopes, err := flags.PrepareFilterScopes(tc.filterArgs)
			require.NoError(t, err)

			eventChan := make(chan trace.Event, 1000)
			config := tracee.Config{
				ChanEvents: eventChan,
				Capabilities: &tracee.CapabilitiesConfig{
					BypassCaps: true,
				},
			}
			config.FilterScopes = filterScopes
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

type testFunc string

const (
	doMagicWrite testFunc = "do_magic_write"
	doLs         testFunc = "do_ls"
	doLsUname    testFunc = "do_ls_uname"
	doDockerRun  testFunc = "do_docker_run"
	doFileOpen   testFunc = "do_file_open"
)

//go:embed tester.sh
var testerscript []byte

// forkAndExecFunction runs a function in `tester.sh` in it's own system process.
// This is so Tracee running in the current pid can pick the command up.
// It returns the output of the process and a possible error.
func forkAndExecFunction(funcName testFunc) ([]byte, error) {

	f, err := os.CreateTemp("", "tracee-integration-test-script")
	if err != nil {
		return nil, fmt.Errorf("couldn't create temp file for script: %w", err)
	}

	_, err = f.Write(testerscript)
	if err != nil {
		return nil, fmt.Errorf("couldn't write temp script: %w", err)
	}

	err = f.Close()
	if err != nil {
		return nil, fmt.Errorf("couldn't close fd for script: %w", err)
	}

	tmpOutputFile, err := os.CreateTemp("/tmp", "tracee-test*")
	if err != nil {
		return nil, fmt.Errorf("couldn't create temporary output file: %w", err)
	}

	err = os.Chmod(f.Name(), 0777)
	if err != nil {
		return nil, fmt.Errorf("couldn't chmod script file: %w", err)
	}

	_, err = syscall.ForkExec(f.Name(), []string{f.Name(), string(funcName), tmpOutputFile.Name()},
		&syscall.ProcAttr{
			Files: []uintptr{0, 1, 2, tmpOutputFile.Fd()},
			Env:   os.Environ(),
		})
	if err != nil {
		return nil, fmt.Errorf("couldn't fork/exec: %w", err)
	}

	// ForkExec doesn't block, wait for output
	time.Sleep(time.Second)

	output, err := ioutil.ReadAll(tmpOutputFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read output: %w", err)
	}
	return output, nil
}
