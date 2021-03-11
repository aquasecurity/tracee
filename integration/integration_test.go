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

// small set of actions to trigger a magic write event
func magicWrite(t *testing.T, gotOutput *bytes.Buffer, expectedOutput string) {
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
func execCommand(t *testing.T, gotOutput *bytes.Buffer, expectedOutput string) {
	execCmd := exec.Command("ls")
	fmt.Println("executing: ", execCmd.String())
	assert.NoError(t, execCmd.Run())

	// check tracee output
	assert.Contains(t, gotOutput.String(), expectedOutput)
}

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

// only capture new pids after tracee
func pidNew(t *testing.T, gotOutput *bytes.Buffer, _ string) {
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
			eventFunc:      magicWrite,
			expectedOutput: "bytes: [102 111 111 46 98 97 114 46 98 97 122]",
		},
		{
			name:           "execute a command",
			args:           []string{"--trace", "comm=ls", "--output=json"},
			eventFunc:      execCommand,
			expectedOutput: `"processName":"ls"`,
		},
		{
			name:      "trace new pids",
			args:      []string{"--trace", "pid=new", "--output", "gotemplate=pid.tmpl"},
			eventFunc: pidNew,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotOutput bytes.Buffer
			done := make(chan bool, 1)
			go loadTracee(t, &gotOutput, done, tc.args...)
			time.Sleep(time.Second * 2) // wait for tracee init

			tc.eventFunc(t, &gotOutput, tc.expectedOutput)
			done <- true
		})
	}
}
