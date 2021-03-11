package integration

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ps "github.com/mitchellh/go-ps"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

// load tracee into memory with args
func loadTracee(t *testing.T, w io.Writer, done chan bool, args ...string) {
	cmd := exec.Command("../tracee-ebpf/dist/tracee-ebpf", args...)
	cmd.Stdout = w
	cmd.Stderr = w

	fmt.Println("running: ", cmd.String())
	assert.NoError(t, cmd.Run())
	<-done
}

// get pid by process name
func getPidByName(t *testing.T, name string) int {
	processes, err := ps.Processes()
	require.NoError(t, err)

	for _, p := range processes {
		if strings.Contains(p.Executable(), name) {
			return p.Pid()
		}
	}
	return -1
}

// small set of actions to trigger a magic write event
func checkMagicwrite(t *testing.T, gotOutput *bytes.Buffer, expectedOutput string) {
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

	// check tracee output
	assert.Contains(t, gotOutput.String(), expectedOutput)
}

// execute a ls command
func checkExeccommand(t *testing.T, gotOutput *bytes.Buffer, expectedOutput string) {
	_, _ = exec.Command("ls").CombinedOutput()

	// check tracee output
	processNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, pname := range processNames {
		assert.Equal(t, "ls", pname)
	}
}

// only capture new pids after tracee
func checkPidnew(t *testing.T, gotOutput *bytes.Buffer, _ string) {
	traceePid := getPidByName(t, "tracee")

	// run a command
	_, _ = exec.Command("ls").CombinedOutput()

	// output should only have events with pids greater (newer) than tracee
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		assert.Greater(t, pid, traceePid)
	}
}

// only capture uids of 0 that are run by comm ls
func checkUidzero(t *testing.T, gotOutput *bytes.Buffer, _ string) {
	_, _ = exec.Command("ls").CombinedOutput()

	// check output length
	require.NotEmpty(t, gotOutput.String())

	// output should only have events with uids of 0
	uids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, u := range uids {
		uid, _ := strconv.Atoi(u)
		require.Zero(t, uid)
	}
}

// only capture pids of 1
func checkPidOne(t *testing.T, gotOutput *bytes.Buffer, _ string) {
	_, _ = exec.Command("init", "q").CombinedOutput()

	// check output length
	require.NotEmpty(t, gotOutput.String())

	// output should only have events with pids of 1
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		require.Equal(t, 1, pid)
	}
}

func checkExecve(t *testing.T, gotOutput *bytes.Buffer, expectedOutput string) {
	_, _ = exec.Command("ls").CombinedOutput()

	// check output length
	require.NotEmpty(t, gotOutput.String())

	// output should only have events with process name of execve
	eventNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, en := range eventNames {
		if len(en) > 0 {
			require.Equal(t, "execve", en)
		}
	}
}

func Test_Events(t *testing.T) {
	var testCases = []struct {
		name           string
		args           []string
		eventFunc      func(*testing.T, *bytes.Buffer, string)
		expectedOutput string
	}{
		{
			name:           "do a file write",
			args:           []string{"--trace", "event=magic_write"},
			eventFunc:      checkMagicwrite,
			expectedOutput: "bytes: [102 111 111 46 98 97 114 46 98 97 122]",
		},
		{
			name:      "execute a command",
			args:      []string{"--trace", "comm=ls", "--output", "gotemplate=processName.tmpl"},
			eventFunc: checkExeccommand,
		},
		{
			name:      "trace new pids",
			args:      []string{"--trace", "pid=new", "--output", "gotemplate=pid.tmpl"},
			eventFunc: checkPidnew,
		},
		{
			name:      "trace uid 0 with comm ls",
			args:      []string{"--trace", "uid=0", "--trace", "comm=ls", "--output", "gotemplate=uid.tmpl"},
			eventFunc: checkUidzero,
		},
		//{
		// TODO: Find a better way to reproduce
		// as this causes side effects
		//name:      "trace pid 1",
		//args:      []string{"--trace", "pid=1", "--output", "gotemplate=pid.tmpl"},
		//eventFunc: checkPidOne,
		//},
		// TODO: Add pid=0,1
		// TODO: Add pid=0 pid=1
		// TODO: Add uid>0
		// TODO: Add pid>0 pid<1000
		// TODO: Add u>0 u!=1000
		{
			name:      "trace only execve events from comm ls",
			args:      []string{"--trace", "event=execve", "--output", "gotemplate=eventName.tmpl"},
			eventFunc: checkExecve,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(st *testing.T) {
			//st.Parallel()

			var gotOutput bytes.Buffer
			done := make(chan bool, 1)
			go loadTracee(st, &gotOutput, done, tc.args...)
			time.Sleep(time.Second * 2) // wait for tracee init

			tc.eventFunc(st, &gotOutput, tc.expectedOutput)
			done <- true
		})
	}
}
