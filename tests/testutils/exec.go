package testutils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const pattern = `'[^']*'|\S+` // split on spaces, but not spaces inside single quotes

var re = regexp.MustCompile(pattern)

// ParseCmd parses a command string into a command and arguments.
func ParseCmd(fullCmd string) (string, []string, error) {
	vals := re.FindAllString(fullCmd, -1)

	if len(vals) == 0 {
		return "", nil, &noCommandSpecified{}
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

// ExecPinnedCmdWithTimeout executes a cmd with a timeout and returns the PID of the process.
func ExecPinnedCmdWithTimeout(command string, timeout time.Duration) (int, error) {
	err := PinProccessToCPU() // pin this goroutine to a specific CPU
	if err != nil {
		return 0, &failedToPinProcessToCPU{command: command, err: err}
	}
	runtime.LockOSThread()         // wire this goroutine to a specific OS thread
	defer runtime.UnlockOSThread() // unlock the thread when we're done

	command, args, err := ParseCmd(command)
	if err != nil {
		return 0, &failedToParseCmd{command: command, err: err}
	}

	cmd := exec.Command(command, args...)
	err = cmd.Start()
	if err != nil {
		return 0, &failedToStartCommand{command: command, err: err}
	}

	pid := cmd.Process.Pid

	cmdDone := make(chan error)
	go func() {
		cmdDone <- cmd.Wait() // wait for command to exit
	}()

	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	select {
	case <-timeoutTicker.C:
		err := cmd.Process.Kill()
		if err != nil {
			return pid, &failedToKillProcess{command: command, err: err}
		}
		return pid, &commandTimedOut{command: command, timeout: timeout}
	case err := <-cmdDone:
		if err != nil {
			return pid, &commandFailed{command: command, err: err}
		}
	}

	return pid, nil
}

// ExecCmdBgWithSudoAndCtx executes a command with sudo in the background, and returns the PID of
// the process and a channel to wait for the command to exit (Check RunningTracee object about how
// to use this).
func ExecCmdBgWithSudoAndCtx(ctx context.Context, command string) (int, chan error) {
	cmdStatus := make(chan error)

	// Use sudo to raise privileges (sysattrs require capabilities).
	if !strings.HasPrefix(command, "sudo") {
		command = fmt.Sprintf("sudo %s", command)
	}

	command, args, err := ParseCmd(command)
	if err != nil {
		fmt.Printf("Failed to parse command\n")
		cmdStatus <- &failedToParseCmd{command: command, err: err}
		return -1, cmdStatus
	}

	cmd := exec.Command(command, args...) // CommandContext can't be used due to sudo privileges
	cmd.Stderr = os.Stderr

	pid := atomic.Int64{}
	wg := sync.WaitGroup{}

	// Start the command in a separate, pinned and locked goroutine (to a single CPU and OS thread).
	// TODO: Adjust here so amount of CPUs is controlled ?

	wg.Add(1)
	go func(pid *atomic.Int64) {
		// Will make the command to inherit the current process' CPU affinity.
		_ = PinProccessToCPU()         // pin this goroutine to a specific CPU
		runtime.LockOSThread()         // wire this goroutine to a specific OS thread
		defer runtime.UnlockOSThread() // unlock the thread when we're done

		err := cmd.Start()
		if err != nil {
			// This isn't a cmd exec failed error, but rather a cmd start failed error.
			pid.Store(-1)
			cmdStatus <- &failedToStartCommand{command: command, err: err}
		} else {
			go func() {
				// Note: cmd exec failed errors are async and happen here on cmd.Wait().
				pid.Store(int64(cmd.Process.Pid)) // store PID
				err := cmd.Wait()                 // block until command exits
				pid.Store(-1)                     // so PID is non positive on failed executions
				cmdStatus <- err                  // signal command exited
			}()
		}

		time.Sleep(1 * time.Second) // wait 1 sec for the command to start (or not)
		wg.Done()                   // signal command started
	}(&pid)

	wg.Wait() // synchronize: wait for 1 sec feedback (cmd has started or not)

	// Kill the command if the context is canceled (and signal that it was killed).

	go func(pid *atomic.Int64) {
		<-ctx.Done()
		p := pid.Load()
		if p > 0 {
			// discover all child processes
			childPIDs, err := DiscoverChildProcesses(int(p))
			if err != nil {
				cmdStatus <- &failedToKillProcess{command: command, err: err}
			}
			// kill all child processes (sudo creates childs in new process group)
			for _, childPID := range childPIDs {
				err := SudoKillProcess(childPID, false)
				if err != nil {
					cmdStatus <- &failedToKillProcess{command: command, err: err}
				}
			}
		}
		cmdStatus <- nil // signal command exited
	}(&pid)

	// Return the PID (or -1) and the channel to wait for the command to exit.
	return int(pid.Load()), cmdStatus
}

// DiscoverChildProcesses discovers all child processes of a given PID.
func DiscoverChildProcesses(pid int) ([]int, error) {
	psCmd := exec.Command("pgrep", "-P", fmt.Sprintf("%d", pid))

	output, err := psCmd.Output()
	if err != nil {
		return nil, err
	}

	childPIDs := strings.Split(strings.TrimSpace(string(output)), "\n")
	childPIDsInts := make([]int, len(childPIDs))

	for i, childPID := range childPIDs {
		childPIDsInts[i], err = strconv.Atoi(strings.TrimSpace(childPID))
		if err != nil {
			return []int{}, err
		}
	}

	return childPIDsInts, nil
}

const (
	SIGTERM = "-15"
	SIGKILL = "-9"
)

// SudoKillProcess kills a process with sudo.
func SudoKillProcess(pid int, force bool) error {
	arg := SIGTERM
	if force {
		arg = SIGKILL
	}

	killCmd := exec.Command("sudo", "kill", arg, fmt.Sprintf("%d", pid))
	killCmd.Stderr = nil
	killCmd.Stdout = nil

	err := killCmd.Run()
	if err != nil {
		return err
	}

	return nil
}

// IsSudoCmdAvailableForThisUser checks if the sudo command is available for the current user.
func IsSudoCmdAvailableForThisUser() bool {
	cmd := exec.Command("sudo", "-n", "true") // can this user use sudo with passwd prompts ?
	cmd.Stderr = nil
	cmd.Stdout = nil

	err := cmd.Run()

	return err == nil
}
