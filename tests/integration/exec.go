package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tests/integration/cpu"
)

const pattern = `'[^']*'|\S+` // split on spaces, but not spaces inside single quotes

var re = regexp.MustCompile(pattern)

// parseCmd parses a command string into a command and arguments
func parseCmd(fullCmd string) (string, []string, error) {
	vals := re.FindAllString(fullCmd, -1)

	if len(vals) == 0 {
		return "", nil, fmt.Errorf("no command specified")
	}
	cmd := vals[0]
	cmd, err := exec.LookPath(cmd)
	if err != nil {
		return "", nil, err
	}
	if !filepath.IsAbs(cmd) {
		cmd, err = filepath.Abs(cmd)
		if err != nil {
			return "", nil, err
		}
	}

	args := vals[1:]
	// remove single quotes from args, since they can confuse exec
	for i, arg := range args {
		args[i] = strings.Trim(arg, "'")
	}

	return cmd, args, nil
}

func execCmd(command string, timeout time.Duration) (int, error) {
	cpu.SetCPUs()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	command, args, err := parseCmd(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parseCmd: %s", err)
		return 0, err
	}

	fmt.Fprintf(os.Stderr, "\texecuting: %s %v\n", command, args)
	cmd := exec.Command(command, args...)
	err = cmd.Start()
	if err != nil {
		return 0, fmt.Errorf("failed to start command: %s", err)
	}

	pid := cmd.Process.Pid

	// wait for the command to finish or for the timeout to expire
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		// timed out
		err := cmd.Process.Kill()
		if err != nil {
			return pid, fmt.Errorf("command timed out, failed to kill process: %s", err)
		}
		return pid, fmt.Errorf("command timed out after %s", timeout)

	case err := <-done:
		// command completed
		if err != nil {
			return pid, fmt.Errorf("command failed with error: %s", err)
		}
		return pid, nil
	}
}
