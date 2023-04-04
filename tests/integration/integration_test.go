package integration

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestInitNamespacesEvent(t *testing.T) {
	procNamespaces := [...]string{"mnt", "cgroup", "pid", "pid_for_children", "time", "time_for_children", "user", "ipc", "net", "uts"}
	evts := events.InitNamespacesEvent()
	initNamespaces := make(map[string]uint32)

	for _, arg := range evts.Args {
		namespaceVale, ok := arg.Value.(uint32)
		assert.Truef(t, ok, "Value of namespace %s is not valid: %v", arg.Name, arg.Value)
		initNamespaces[arg.Name] = namespaceVale
	}

	for _, namespace := range procNamespaces {
		assert.Contains(t, initNamespaces, namespace)
		assert.NotZero(t, initNamespaces[namespace])
	}
}

// small set of actions to trigger a magic write event
func checkMagicwrite(t *testing.T, gotOutput *eventOutput) {

	_, err := forkAndExecFunction(doMagicWrite)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check tracee output
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		assert.Equal(t, []byte(evt.EventName), []byte("magic_write"))
	}
}

// execute a ls command
func checkExeccommand(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check tracee output
	processNames := []string{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		processNames = append(processNames, evt.ProcessName)
	}
	for _, pname := range processNames {
		assert.Equal(t, "ls", pname)
	}
}

// only capture new pids after tracee
func checkPidnew(t *testing.T, gotOutput *eventOutput) {
	traceePid := os.Getpid()

	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// output should only have events with pids greater (newer) than tracee
	pids := []int{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		if evt.ProcessName == "ls" {
			pids = append(pids, evt.ProcessID)
		}
	}
	for _, pid := range pids {
		assert.Greater(t, pid, traceePid)
	}
}

// only capture uids of 0 that are run by comm ls
func checkUidZero(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	// output should only have events with uids of 0
	uids := []int{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		uids = append(uids, evt.UserID)
	}
	for _, uid := range uids {
		require.Zero(t, uid)
	}
}

// trigger ls from uid 0 (tests run as root) and check if empty
func checkUidNonZero(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), false)

	// check output length
	assert.Empty(t, gotOutput)
}

// check that execve event is called
func checkExecve(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	// output should only have events with event name of execve
	eventNames := []string{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		eventNames = append(eventNames, evt.EventName)
	}
	for _, en := range eventNames {
		if len(en) > 0 {
			require.Equal(t, "execve", en)
		}
	}
}

// check for filesystem set when ls is invoked
func checkSetFs(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	require.NotEmpty(t, gotOutput)

	expectedSyscalls := getAllSyscallsInSet("fs")

	// output should only have events with events in the set of filesystem syscalls
	eventNames := []string{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		eventNames = append(eventNames, evt.EventName)
	}
	for _, en := range eventNames {
		require.Contains(t, expectedSyscalls, en)
	}
}

func checkNewContainers(t *testing.T, gotOutput *eventOutput) {
	// pull alpine image first otherwise pull might happen
	// on docker run and cause output to be too delayed
	_, err := forkAndExecFunction(doPullAlpine)
	require.NoError(t, err)

	// start test
	containerIdBytes, err := forkAndExecFunction(doDockerRun)
	require.NoError(t, err)
	containerId := strings.TrimSuffix(string(containerIdBytes), "\n")
	require.NotEmpty(t, containerId)
	containerIds := []string{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		containerIds = append(containerIds, evt.Container.ID)
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

func checkSecurityFileOpenExecve(t *testing.T, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doFileOpen)
	require.NoError(t, err)

	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		assert.Equal(t, "execve", evt.Syscall)
	}
}

func checkDockerdBinaryFilter(t *testing.T, gotOutput *eventOutput) {
	dockerdPidBytes, err := forkAndExecFunction(getDockerdPid)
	require.NoError(t, err)
	dockerdPidString := strings.TrimSuffix(string(dockerdPidBytes), "\n")
	dockerdPid, err := strconv.ParseInt(dockerdPidString, 10, 64)
	require.NoError(t, err)
	_, err = forkAndExecFunction(doDockerRun)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	processIds := []int{}
	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		processIds = append(processIds, evt.ProcessID)
	}
	assert.Contains(t, processIds, int(dockerdPid))
}

func TestEventFilters(t *testing.T) {
	testCases := []struct {
		name       string
		filterArgs []string
		eventFunc  func(*testing.T, *eventOutput)
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
			filterArgs: []string{"container=new", "event!=container_create,container_remove"},
			eventFunc:  checkNewContainers,
		},
		{
			name:       "trace only security_file_open from \"execve\" syscall",
			filterArgs: []string{"event=security_file_open", "security_file_open.context.syscall=execve"},
			eventFunc:  checkSecurityFileOpenExecve,
		},
		{
			name:       "trace only events from \"/usr/bin/dockerd\" binary and contain it's pid",
			filterArgs: []string{"bin=/usr/bin/dockerd"},
			eventFunc:  checkDockerdBinaryFilter,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			filterMap, err := flags.PrepareFilterMapFromFlags(tc.filterArgs)
			require.NoError(t, err)

			policies, err := flags.CreatePolicies(filterMap)

			require.NoError(t, err)

			eventChan := make(chan trace.Event, 1000)
			config := tracee.Config{
				ChanEvents: eventChan,
				Capabilities: &tracee.CapabilitiesConfig{
					BypassCaps: true,
				},
			}
			config.Policies = policies
			eventOutput := &eventOutput{}

			go func() {
				for {
					select {
					case evt, ok := <-eventChan:
						if !ok {
							return
						}
						eventOutput.addEvent(evt)

					case <-ctx.Done():
						return
					}
				}
			}()

			trc := startTracee(t, ctx, config, nil, nil)

			waitforTraceeStart(t, trc, time.Now())

			tc.eventFunc(t, eventOutput)

			cancel()
		})
	}
}

func checkPolicySecurityFileOpenLs(t *testing.T, pols *policy.Policies, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLs)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	output := gotOutput.getEventsCopy()
	pol1, err := pols.Lookup(0)
	require.NoError(t, err)
	for _, evt := range output {
		// ls - policy 1
		assert.Equal(t, "ls", evt.ProcessName, "ProcessName")
		assert.Equal(t, uint64(1<<0), evt.MatchedPolicies, "MatchedPolicies")
		assert.Equal(t, []string{pol1.Name}, evt.MatchedPoliciesNames, "MatchedPoliciesNames")
		arg, err := helpers.GetTraceeArgumentByName(evt, "pathname", helpers.GetArgOps{DefaultArgs: false})
		require.NoError(t, err)
		assert.Contains(t, arg.Value, "integration")
	}
}

// checkExecveOnPolicies1And2 demands an ordered events submission
func checkExecveOnPolicies1And2(t *testing.T, pols *policy.Policies, gotOutput *eventOutput) {
	_, err := forkAndExecFunction(doLsUname)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	// check output length
	output := gotOutput.getEventsCopy()
	require.Len(t, output, 2)
	var evts [2]trace.Event

	// output should only have events with event name of execve
	for i, evt := range output {
		assert.Equal(t, "sched_process_exit", evt.EventName)
		evts[i] = evt
	}
	pol1, err := pols.Lookup(0)
	require.NoError(t, err)
	pol2, err := pols.Lookup(1)
	require.NoError(t, err)

	// ls - policy 1
	assert.Equal(t, evts[0].ProcessName, "ls")
	assert.Equal(t, uint64(1<<0), evts[0].MatchedPolicies, "MatchedPolicies")
	assert.Equal(t, []string{pol1.Name}, evts[0].MatchedPoliciesNames, "MatchedPoliciesNames")

	// uname - policy 2
	assert.Equal(t, evts[1].ProcessName, "uname")
	assert.Equal(t, uint64(1<<1), evts[1].MatchedPolicies, "MatchedPolicies")
	assert.Equal(t, []string{pol2.Name}, evts[1].MatchedPoliciesNames, "MatchedPoliciesNames")
}

func checkUnameAndWhoOnPoliciesWithBinaryScope(t *testing.T, pols *policy.Policies, gotOutput *eventOutput) {
	var err error
	_, err = forkAndExecFunction(doUnameWho)
	require.NoError(t, err)

	waitForTraceeOutput(t, gotOutput, time.Now(), true)

	output := gotOutput.getEventsCopy()
	for _, evt := range output {
		procName := evt.ProcessName
		if procName != "uname" && procName != "who" {
			t.Fail()
		}
	}
}

func TestEventPolicies(t *testing.T) {
	testCases := []struct {
		name      string
		policies  []flags.PolicyFile
		eventFunc func(*testing.T, *policy.Policies, *eventOutput)
	}{
		{
			name: "global scope - single event - args",
			policies: []flags.PolicyFile{
				{
					Name:          "global_scope_single_event",
					Description:   "global scope - single event",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []flags.Rule{
						{
							Event:  "security_file_open",
							Filter: []string{"args.pathname=*integration"},
						},
					},
				},
			},
			eventFunc: checkPolicySecurityFileOpenLs,
		},
		{
			name: "global scope - single event - comm",
			policies: []flags.PolicyFile{
				{
					Name:          "global_scope_single_event_1",
					Description:   "global scope - single event 1",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []flags.Rule{
						{
							Event:  "sched_process_exit",
							Filter: []string{"comm=ls"},
						},
					},
				},
				{
					Name:          "global_scope_single_event_2",
					Description:   "global scope - single event 2",
					Scope:         []string{"global"},
					DefaultAction: "log",
					Rules: []flags.Rule{
						{
							Event:  "sched_process_exit",
							Filter: []string{"comm=uname"},
						},
					},
				},
			},
			eventFunc: checkExecveOnPolicies1And2,
		},
		{
			name: "binary scope - single event",
			policies: []flags.PolicyFile{
				{
					Name:          "binary_scope_single_event_1",
					Description:   "binary scope - single event 1",
					Scope:         []string{"binary=/usr/bin/uname"},
					DefaultAction: "log",
					Rules: []flags.Rule{
						{
							Event: "sched_process_exit",
						},
					},
				},
				{
					Name:          "binary_scope_single_event_2",
					Description:   "binary scope - single event 2",
					Scope:         []string{"binary=/usr/bin/who"},
					DefaultAction: "log",
					Rules: []flags.Rule{
						{
							Event: "sched_process_exit",
						},
					},
				},
			},
			eventFunc: checkUnameAndWhoOnPoliciesWithBinaryScope,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			filterMap, err := flags.PrepareFilterMapFromPolicies(tc.policies)
			require.NoError(t, err)

			policies, err := flags.CreatePolicies(filterMap)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())

			eventChan := make(chan trace.Event, 1000)
			config := tracee.Config{
				ChanEvents: eventChan,
				Capabilities: &tracee.CapabilitiesConfig{
					BypassCaps: true,
				},
			}
			config.Policies = policies
			eventOutput := &eventOutput{}

			go func() {
				for {
					select {
					case evt, ok := <-eventChan:
						if !ok {
							return
						}
						eventOutput.addEvent(evt)

					case <-ctx.Done():
						return
					}
				}
			}()

			trc := startTracee(t, ctx, config, nil, nil)

			waitforTraceeStart(t, trc, time.Now())

			tc.eventFunc(t, policies, eventOutput)

			cancel()
		})
	}
}

type testFunc string

const (
	doMagicWrite  testFunc = "do_magic_write"
	doLs          testFunc = "do_ls"
	doLsUname     testFunc = "do_ls_uname"
	doUnameWho    testFunc = "do_uname_who"
	doDockerRun   testFunc = "do_docker_run"
	doPullAlpine  testFunc = "do_docker_pull_alpine"
	doFileOpen    testFunc = "do_file_open"
	getDockerdPid testFunc = "get_dockerd_pid"
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

	output, err := io.ReadAll(tmpOutputFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read output: %w", err)
	}
	return output, nil
}
