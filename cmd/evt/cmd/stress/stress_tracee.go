package stress

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// checkTraceeNotRunning verifies no Tracee instance is currently running
func (s *stress) checkTraceeNotRunning() error {
	const traceePidFile = "/tmp/tracee/tracee.pid"
	var foundRunning bool
	var errorMsgs []string

	// Check 1: Look for Tracee PID file
	if pidData, err := os.ReadFile(traceePidFile); err == nil {
		pidStr := strings.TrimSpace(string(pidData))
		if pidStr != "" {
			// PID file exists with a PID, check if process is still running
			if err := exec.Command("kill", "-0", pidStr).Run(); err == nil {
				// Process is running
				foundRunning = true
				errorMsgs = append(errorMsgs,
					fmt.Sprintf("  - Tracee running with PID %s (from PID file: %s)", pidStr, traceePidFile))
			} else {
				// PID file exists but process is dead - warn about stale file
				s.printf("Warning: Found stale Tracee PID file at %s (PID: %s)\n", traceePidFile, pidStr)
			}
		}
	}

	// Check 2: Look for ANY tracee process (not just our specific binary)
	// This catches any tracee binary that might be running
	cmd := exec.Command("pgrep", "-a", "tracee")
	output, err := cmd.Output()

	if err == nil && len(output) > 0 {
		// Found running tracee processes
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			// pgrep -a output format: "PID command line"
			if strings.Contains(line, "tracee") && !strings.Contains(line, "pgrep") {
				foundRunning = true
				errorMsgs = append(errorMsgs, fmt.Sprintf("  - %s", line))
			}
		}
	}

	if foundRunning {
		return fmt.Errorf(
			"tracee is already running:\n%s\n\n"+
				"Please stop all Tracee instances before running stress test.\n"+
				"You can stop them with: sudo pkill -TERM tracee",
			strings.Join(errorMsgs, "\n"),
		)
	}

	return nil
}

// startTracee starts Tracee as a subprocess
func (s *stress) startTracee() error {
	errCh := make(chan error, 1)
	logFilePath := fmt.Sprintf("/tmp/tracee-stress-%s.log", time.Now().Format("20060102-150405"))

	go func() {
		// Build Tracee arguments
		var args []string

		// Add container scope filter
		containerScope := fmt.Sprintf("container=%s", strings.Join(s.containerIDs, ","))
		args = append(args, "--scope", containerScope)

		// Add events
		for _, evt := range s.eventNames {
			args = append(args, "--events", evt)
		}

		// Add output (Tracee supports "none" as a valid value)
		args = append(args, "--output", s.traceeOutput)

		// Add server endpoints for profiling and metrics
		// These are --server flags, not standalone flags
		if s.metrics {
			args = append(args, "--server", "metrics")
		}
		if s.pprof {
			args = append(args, "--server", "pprof")
		}
		if s.pyroscope {
			args = append(args, "--server", "pyroscope")
		}

		s.printf("Starting Tracee: %s %v\n", s.traceeBinary, args)
		s.printf("Tracee logs: %s\n", logFilePath)

		// Create command with process group
		cmd := exec.CommandContext(s.ctx, s.traceeBinary, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true, // Create new process group for better control
		}
		cmd.Cancel = func() error {
			// Custom cancellation sends SIGTERM
			return cmd.Process.Signal(syscall.SIGTERM)
		}

		// Create log file for Tracee output
		logFile, err := os.Create(logFilePath)
		if err != nil {
			errCh <- fmt.Errorf("creating log file: %w", err)
			return
		}
		defer logFile.Close()

		cmd.Stdout = logFile
		cmd.Stderr = logFile

		// Start Tracee
		err = cmd.Start()
		if err != nil {
			errCh <- fmt.Errorf("starting Tracee: %w", err)
			return
		}

		s.mu.Lock()
		s.traceeCmd = cmd
		s.traceePID = cmd.Process.Pid
		s.traceeExitCh = make(chan error, 1)
		pid := s.traceePID
		exitCh := s.traceeExitCh
		s.mu.Unlock()

		s.printf("Tracee started with PID: %d\n", pid)
		s.printf("Waiting for Tracee to initialize...\n")

		// Wait to ensure Tracee started successfully and didn't crash immediately
		cmdWaitChan := s.waitForCommand(cmd)
		initialWait := 3 * time.Second
		select {
		case err = <-cmdWaitChan:
			// Tracee crashed - read the log file to show what went wrong
			logFile.Sync() // Ensure logs are flushed
			logContents, readErr := os.ReadFile(logFilePath)
			errMsg := fmt.Sprintf("tracee finished: %v", err)
			if readErr == nil && len(logContents) > 0 {
				errMsg += fmt.Sprintf("\n\nTracee log output (%s):\n%s", logFilePath, string(logContents))
			} else {
				errMsg += fmt.Sprintf("\n\nTracee log file: %s", logFilePath)
			}
			errCh <- fmt.Errorf("%s", errMsg)
			exitCh <- err // Signal that Tracee exited
			return
		case <-time.After(initialWait):
			// Tracee is still running after initial wait
		}

		// Additional cooldown for Tracee to finish initializing
		// Similar to tracee_start.sh which waits 5 seconds after PID file appears
		cooldown := 5 * time.Second
		s.printf("Tracee running, waiting %v for initialization to complete...\n", cooldown)
		time.Sleep(cooldown)

		// Signal ready
		s.printf("Tracee initialization complete\n")
		errCh <- nil

		// Continue monitoring Tracee in background
		err = <-cmdWaitChan
		exitCh <- err // Signal that Tracee exited (might be nil or error)
		if err != nil {
			s.printErrf("Tracee finished: %v\n", err)
		}
	}()

	// Wait for Tracee to be ready or fail
	return <-errCh
}

// stopTracee gracefully stops Tracee
func (s *stress) stopTracee() error {
	s.mu.Lock()
	cmd := s.traceeCmd
	pid := s.traceePID
	exitCh := s.traceeExitCh
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil // Tracee not running
	}

	s.printf("Stopping Tracee (PID: %d)...\n", pid)

	// Check if Tracee already exited
	select {
	case err := <-exitCh:
		if err != nil {
			s.printErrf("Tracee already exited with error: %v\n", err)
		} else {
			s.printf("Tracee already exited successfully\n")
		}
		return err
	default:
		// Tracee still running, proceed with graceful shutdown
	}

	// Send SIGTERM for graceful shutdown (like tracee_stop.sh)
	s.printf("Sending SIGTERM for graceful shutdown...\n")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		s.printErrf("Failed to send SIGTERM to Tracee: %v\n", err)
		// If we can't send SIGTERM, try SIGKILL
		if killErr := cmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("failed to kill Tracee: %w", killErr)
		}
		// Wait for exit
		<-exitCh
		return nil
	}

	// Wait for graceful shutdown with polling (like tracee_stop.sh)
	timeout := 10 * time.Second
	pollInterval := 500 * time.Millisecond
	deadline := time.Now().Add(timeout)

	s.printf("Waiting up to %v for graceful shutdown...\n", timeout)

	for time.Now().Before(deadline) {
		select {
		case err := <-exitCh:
			// Process exited gracefully
			if err != nil {
				s.printErrf("Tracee exited with error: %v\n", err)
			} else {
				s.printf("Tracee stopped gracefully\n")
			}
			return err
		case <-time.After(pollInterval):
			// Check if process is still alive using kill -0
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				// Process is gone, wait for exitCh to confirm
				select {
				case err := <-exitCh:
					if err != nil {
						s.printErrf("Tracee exited with error: %v\n", err)
					} else {
						s.printf("Tracee stopped gracefully\n")
					}
					return err
				case <-time.After(100 * time.Millisecond):
					// Shouldn't happen, but handle it
					s.printf("Tracee stopped (process gone)\n")
					return nil
				}
			}
			// Still alive, continue polling
		}
	}

	// Timeout reached, force kill
	s.printErrf("Tracee did not stop within %v, sending SIGKILL...\n", timeout)
	if err := cmd.Process.Kill(); err != nil {
		s.printErrf("Failed to send SIGKILL: %v\n", err)
	}

	// Wait for exit channel with a short timeout
	select {
	case err := <-exitCh:
		s.printf("Tracee terminated (SIGKILL)\n")
		return err
	case <-time.After(2 * time.Second):
		s.printErrf("Tracee may still be running after SIGKILL\n")
		return fmt.Errorf("tracee did not stop after SIGKILL")
	}
}

// waitForCommand waits for a command to finish
func (s *stress) waitForCommand(cmd *exec.Cmd) <-chan error {
	done := make(chan error, 1)

	go func() {
		done <- cmd.Wait()
		close(done)
	}()

	return done
}
