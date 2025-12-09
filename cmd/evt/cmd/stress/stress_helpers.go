package stress

import (
	"fmt"
	"os/exec"
)

// waitForUserInput waits for the user to press Enter
func (s *stress) waitForUserInput() error {
	// Use a channel to handle both user input and context cancellation
	done := make(chan error, 1)

	go func() {
		var input string
		_, err := fmt.Scanln(&input)
		done <- err
	}()

	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case err := <-done:
		if err != nil && err.Error() != "unexpected newline" {
			// Ignore "unexpected newline" which happens when user just presses Enter
			return err
		}
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
		return fmt.Errorf("container image %s not found: %w\nHint: Build it with 'make evt-container'", s.containerImage, err)
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
