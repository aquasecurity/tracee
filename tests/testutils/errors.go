package testutils

import (
	"fmt"
	"time"
)

// noCommandSpecified is returned when no command is specified.
type noCommandSpecified struct{}

func (e *noCommandSpecified) Error() string {
	return "no command specified"
}

// failedToStartCommand is returned when a command fails to start.
type failedToStartCommand struct {
	command string
	err     error
}

func (e *failedToStartCommand) Error() string {
	return fmt.Sprintf("failed to start command '%s': %s", e.command, e.err)
}

// failedToKillProcess is returned when a command times out and fails to kill the process.
type failedToKillProcess struct {
	command string
	err     error
}

func (e *failedToKillProcess) Error() string {
	return fmt.Sprintf("failed to kill command '%s': %s", e.command, e.err)
}

// commandTimedOut is returned when a command times out.
type commandTimedOut struct {
	command string
	timeout time.Duration
}

func (e *commandTimedOut) Error() string {
	return fmt.Sprintf("command '%s' timed out after %s", e.command, e.timeout)
}

// commandFailed is returned when a command fails.
type commandFailed struct {
	command string
	err     error
}

func (e *commandFailed) Error() string {
	return fmt.Sprintf("command '%s' failed with error: %s", e.command, e.err)
}

// failedToPinProcessToCPU is returned when a command fails to pin to a CPU.
type failedToPinProcessToCPU struct {
	command string
	err     error
}

func (e *failedToPinProcessToCPU) Error() string {
	return fmt.Sprintf("failed to pin command '%s' to CPU: %s", e.command, e.err)
}

// failedToParseCmd is returned when a command fails to parse.
type failedToParseCmd struct {
	command string
	err     error
}

func (e *failedToParseCmd) Error() string {
	return fmt.Sprintf("failed to parse command '%s': %s", e.command, e.err)
}

// failedToStartTracee is returned when tracee fails to start.
type failedToStartTracee struct {
	command string
	err     error
}

func (e *failedToStartTracee) Error() string {
	return fmt.Sprintf("failed to start tracee: %s", e.err)
}
