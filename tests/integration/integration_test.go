//go:build integration
// +build integration

package integration_test

import (
	"bytes"
	"errors"
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

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/mitchellh/go-ps"
	"github.com/onsi/gomega/gexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	CheckTimeout = time.Second * 2
)

func getTraceeBinaryPath() (string, error) {
	traceePath, ok := os.LookupEnv("TRC_BIN")
	if !ok {
		return "", errors.New("tracee-ebpf path is not set with TRC_BIN env")
	}

	if _, err := os.Stat(traceePath); os.IsNotExist(err) {
		return "", fmt.Errorf("tracee-ebpf binary does not exist: %s: %w", traceePath, err)
	}
	return traceePath, nil
}

// load tracee into memory with args
func loadTracee(t *testing.T, traceeBinPath string, w io.Writer, done chan bool, args ...string) {
	cmd := exec.Command(traceeBinPath, args...)
	t.Logf("running command: %s\n", cmd.String())

	session, err := gexec.Start(cmd, w, w)
	require.NoError(t, err)
	<-done
	session.Interrupt()
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

// wait for tracee buffer to fill or timeout to occur, whichever comes first
func waitForTraceeOutput(gotOutput *bytes.Buffer, now time.Time) {
	for {
		if len(gotOutput.String()) > 0 || (time.Since(now) > CheckTimeout) {
			break
		}
	}
}

// small set of actions to trigger a magic write event
func checkMagicwrite(t *testing.T, gotOutput *bytes.Buffer) {
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

	waitForTraceeOutput(gotOutput, time.Now())

	// check tracee output
	assert.Contains(t, gotOutput.String(), `[102 111 111 46 98 97 114 46 98 97 122]`)
}

// execute a ls command
func checkExeccommand(t *testing.T, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check tracee output
	processNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, pname := range processNames {
		assert.Equal(t, "ls", pname)
	}
}

// only capture new pids after tracee
func checkPidnew(t *testing.T, gotOutput *bytes.Buffer) {
	traceePid := getPidByName(t, "tracee")

	// run a command
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// output should only have events with pids greater (newer) than tracee
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		assert.Greater(t, pid, traceePid)
	}
}

// only capture uids of 0 that are run by comm ls
func checkUidzero(t *testing.T, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

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
func checkPidOne(t *testing.T, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("init", "q").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(t, gotOutput.String())

	// output should only have events with pids of 1
	pids := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		require.Equal(t, 1, pid)
	}
}

// check that execve event is called
func checkExecve(t *testing.T, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(t, gotOutput.String())

	// output should only have events with event name of execve
	eventNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
	for _, en := range eventNames {
		if len(en) > 0 {
			require.Equal(t, "execve", en)
		}
	}
}

// check for filesystem set when ls is invoked
func checkSetFs(t *testing.T, gotOutput *bytes.Buffer) {
	_, _ = exec.Command("ls").CombinedOutput()

	waitForTraceeOutput(gotOutput, time.Now())

	// check output length
	require.NotEmpty(t, gotOutput.String())

	expectedSyscalls := getAllSyscallsInSet("fs")

	// output should only have events with events in the set of filesystem syscalls
	eventNames := strings.Split(strings.TrimSpace(gotOutput.String()), "\n")
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

// This test is nice, but very hard to run in CI pipeline because it requires
// root privileges. It also requires the path to the tracee-ebpf executable to
// be set with the TRC_BIN environment variable.
//
// To run this test manually you can do the following:
//    make tracee-ebpf
//
//    sudo -i
//    export PATH=$PATH:/usr/local/go/bin
//
//    TRC_BIN=$PWD/dist/tracee-ebpf \
//    GOOS=linux GOARCH=amd64 \
//    CC=clang \
//    CGO_CFLAGS="-I$PWD/dist/libbpf" \
//    CGO_LDFLAGS="-lelf -lz $PWD/dist/libbpf/libbpf.a" \
//    go test \
//      -tags ebpf,integration \
//      -v \
//      -run "Test_Events" ./tests/integration/...
//
// Remember to comment out t.Skip statement.
func Test_Events(t *testing.T) {
	t.Skip("This test requires root privileges")

	var testCases = []struct {
		name       string
		args       []string
		eventFunc  func(*testing.T, *bytes.Buffer)
		goTemplate string
	}{
		{
			name:       "do a file write",
			args:       []string{"--trace", "event=magic_write"},
			eventFunc:  checkMagicwrite,
			goTemplate: "{{ .Args }}\n",
		},
		{
			name:       "execute a command",
			args:       []string{"--trace", "comm=ls"},
			eventFunc:  checkExeccommand,
			goTemplate: "{{ .ProcessName }}\n",
		},
		{
			name:       "trace new pids",
			args:       []string{"--trace", "pid=new"},
			eventFunc:  checkPidnew,
			goTemplate: "{{ .ProcessID }}\n",
		},
		{
			name:       "trace uid 0 with comm ls",
			args:       []string{"--trace", "uid=0", "--trace", "comm=ls"},
			eventFunc:  checkUidzero,
			goTemplate: "{{ .UserID }}\n",
		},
		{
			name:       "trace pid 1",
			args:       []string{"--trace", "pid=1"},
			eventFunc:  checkPidOne,
			goTemplate: "{{ .ProcessID }}\n",
		},
		//TODO: Add pid=0,1
		//TODO: Add pid=0 pid=1
		//TODO: Add uid>0
		//TODO: Add pid>0 pid<1000
		//TODO: Add u>0 u!=1000
		{
			name:       "trace only execve events from comm ls",
			args:       []string{"--trace", "event=execve"},
			eventFunc:  checkExecve,
			goTemplate: "{{ .EventName }}\n",
		},
		{
			name:       "trace filesystem events from comm ls",
			args:       []string{"--trace", "s=fs", "--trace", "comm=ls"},
			eventFunc:  checkSetFs,
			goTemplate: "{{ .EventName }}\n",
		},
		{
			name:       "trace only execve events that ends with ls",
			args:       []string{"--trace", "event=execve", "--trace", "execve.pathname=*ls"},
			eventFunc:  checkExeccommand,
			goTemplate: "{{ .EventName }}\n",
		},
		{
			name:       "trace only execve events that starts with /bin",
			args:       []string{"--trace", "event=execve", "--trace", "execve.pathname=/bin*"},
			eventFunc:  checkExeccommand,
			goTemplate: "{{ .EventName }}\n",
		},
		{
			name:       "trace only execve events that contains l",
			args:       []string{"--trace", "event=execve", "--trace", "execve.pathname=*l*"},
			eventFunc:  checkExeccommand,
			goTemplate: "{{ .EventName }}\n",
		},
		// TODO: Add --capture tests
	}

	bin, err := getTraceeBinaryPath()
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {

			if tc.goTemplate != "" {
				f, _ := ioutil.TempFile("", fmt.Sprintf("%s-*", tc.name))
				_, _ = f.WriteString(tc.goTemplate)
				defer func() {
					_ = os.Remove(f.Name())
				}()

				tc.args = append(tc.args, "--output", fmt.Sprintf("gotemplate=%s", f.Name()))
			}

			var gotOutput bytes.Buffer
			done := make(chan bool, 1)
			go loadTracee(st, bin, &gotOutput, done, tc.args...)
			time.Sleep(time.Second) // wait for tracee init

			tc.eventFunc(st, &gotOutput)
			done <- true
		})
	}
}
