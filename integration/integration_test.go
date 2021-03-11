package integration

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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
func magicWrite(t *testing.T) {
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
}

// execute a ls command
func execCommand(t *testing.T) {
	execCmd := exec.Command("ls")
	fmt.Println("executing: ", execCmd.String())
	assert.NoError(t, execCmd.Run())
}

func Test_Events(t *testing.T) {
	var testCases = []struct {
		name           string
		args           []string
		eventFunc      func(*testing.T)
		expectedOutput string
	}{
		{
			name:           "event: magic write",
			args:           []string{"--trace", "event=magic_write"},
			eventFunc:      magicWrite,
			expectedOutput: "bytes: [102 111 111 46 98 97 114 46 98 97 122]",
		},
		{
			name:           "command: ls",
			args:           []string{"--trace", "comm=ls", "--output=json"},
			eventFunc:      execCommand,
			expectedOutput: `"processName":"ls"`,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var expectedOutput bytes.Buffer
			done := make(chan bool, 1)
			go loadTracee(t, &expectedOutput, done, tc.args...)
			time.Sleep(time.Second * 2) // wait for tracee init

			tc.eventFunc(t)

			done <- true
			assert.Contains(t, expectedOutput.String(), tc.expectedOutput, tc.name)
		})
	}
}
