package stress

import (
	"fmt"
	"os"
	"os/exec"
)

// waitForUserInput waits for the user to press Enter
func (s *stress) waitForUserInput() error {
	// Use a channel to race between user input and context cancellation
	inputReceived := make(chan struct{})

	go func() {
		// This goroutine will block on stdin read until user provides input.
		// Note: It cannot be interrupted by context cancellation due to Go's
		// standard library limitations. However, this is acceptable because:
		// 1. It only affects interactive mode (rare in automated testing)
		// 2. Ctrl+C (SIGINT) will terminate the entire process anyway
		// 3. If context is cancelled, we return immediately below
		var input string
		_, _ = fmt.Scanln(&input)
		close(inputReceived)
	}()

	select {
	case <-s.ctx.Done():
		// Context cancelled (e.g., timeout or Ctrl+C)
		// The goroutine above will remain blocked on stdin, but that's okay
		// because the entire program will exit soon
		return s.ctx.Err()
	case <-inputReceived:
		// User pressed Enter
		return nil
	}
}

// validateDockerAvailable checks if docker is available
func (s *stress) validateDockerAvailable() error {
	cmd := exec.CommandContext(s.ctx, "docker", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker not available: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// validateContainerImage checks if the container image exists
func (s *stress) validateContainerImage() error {
	cmd := exec.CommandContext(s.ctx, "docker", "image", "inspect", s.containerImage)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf(`container image %q not found

The trigger runner container is required to execute event triggers in isolation.

To build the default image (run from repository root):
  make evt-trigger-runner

To build with a custom name (run from repository root):
  EVT_TRIGGER_RUNNER_IMAGE=%s make evt-trigger-runner

To use a specific image:
  evt stress --image <your-image:tag> ...

Error: %w`, s.containerImage, s.containerImage, err)
	}
	return nil
}

// validateTraceeBinary checks if the tracee binary exists and is executable
func (s *stress) validateTraceeBinary() error {
	if !s.autoTracee {
		// If not auto-starting tracee, skip validation
		return nil
	}

	info, err := os.Stat(s.traceeBinary)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf(`tracee binary not found at %q

The tracee binary is required for stress testing when using --auto-tracee (default).

To build tracee:
  make tracee

To use a different binary path:
  evt stress --tracee-binary /path/to/tracee ...

To manually start tracee instead:
  evt stress --auto-tracee=false ...

Note: Use --keep-tracee to prevent automatic termination after the stress test`, s.traceeBinary)
		}
		return fmt.Errorf("failed to check tracee binary %q: %w", s.traceeBinary, err)
	}

	// Check if it's executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("tracee binary %q exists but is not executable\n\nMake it executable with: chmod +x %s", s.traceeBinary, s.traceeBinary)
	}

	return nil
}

// Print helpers for cleaner code
func (s *stress) printf(format string, args ...any) {
	s.cmd.Printf(format, args...)
}

func (s *stress) println(args ...any) {
	s.cmd.Println(args...)
}

func (s *stress) printErrf(format string, args ...any) {
	s.cmd.PrintErrf(format, args...)
}

func (s *stress) printErrln(args ...any) {
	s.cmd.PrintErrln(args...)
}
