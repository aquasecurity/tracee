package stress

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// triggerConfig holds configuration for a single trigger
type triggerConfig struct {
	event     string
	instances int
	ops       int32
	sleep     string
}

// stress orchestrates containers running evt trigger commands
type stress struct {
	triggers       []triggerConfig
	containerImage string
	dryRun         bool

	// Tracee configuration
	traceeBinary      string
	traceeOutput      string
	autoTracee        bool
	eventNames        []string // Event names to pass to Tracee
	metrics           bool     // Enable metrics collection
	pprof             bool     // Enable pprof profiling
	pyroscope         bool     // Enable pyroscope profiling
	keepTracee        bool     // Keep Tracee running after stress test
	waitBeforeTrigger bool     // Wait for user input before triggering events

	ctx context.Context
	cmd *cobra.Command

	// Runtime state
	containerIDs []string
	traceeCmd    *exec.Cmd
	traceePID    int
	traceeExitCh chan error // Channel to signal Tracee exit
	mu           sync.Mutex
}

func (s *stress) run() error {
	s.printf("Starting stress test orchestration\n")
	s.printf("Triggers configured: %d\n", len(s.triggers))
	for i, tc := range s.triggers {
		s.printf("  [%d] %s: instances=%d, ops=%d, sleep=%s\n",
			i+1, tc.event, tc.instances, tc.ops, tc.sleep)
	}
	s.printf("Container image: %s\n", s.containerImage)

	if s.dryRun {
		s.printf("\nDry run mode - showing what would be executed:\n\n")
		return s.dryRunFlow()
	}

	return s.executeFlow()
}

func (s *stress) dryRunFlow() error {
	s.printf("=== Phase 1: Start Containers ===\n")
	for _, tc := range s.triggers {
		containerName := s.getContainerName(tc.event)
		inContainerCmd := s.buildInContainerCommand(tc)

		s.printf("\nTrigger: %s\n", tc.event)
		s.printf("  Container name: %s\n", containerName)
		s.printf("  Parallel workers: %d\n", tc.instances)
		s.printf("  Operations per worker: %d\n", tc.ops)
		s.printf("  Sleep between ops: %s\n", tc.sleep)
		s.printf("  Total ops: %d (workers × ops)\n", tc.instances*int(tc.ops))
		s.printf("  Docker command:\n")
		s.printf("    docker run -d --name %s %s %s\n",
			containerName, s.containerImage, inContainerCmd)
		s.printf("  In-container command breakdown:\n")
		s.printf("    - Runs single evt trigger process with %d parallel workers\n", tc.instances)
		s.printf("    - Command: %s\n", inContainerCmd)
		s.printf("    - Waits for SIGUSR1 before starting\n")
	}

	s.printf("\n=== Phase 2: Collect Container IDs ===\n")
	s.printf("  Would verify %d containers started successfully\n", len(s.triggers))
	s.printf("  Would extract container IDs for filtering\n")

	s.printf("\n=== Phase 3: Configure & Start Tracee ===\n")
	s.printf("  Would generate scope filter: --scope container=<id1>,<id2>,...\n")
	s.printf("  Would start: tracee with container scope filters\n")
	s.printf("  Example: tracee --scope container=abc123,def456 --events ...\n")

	// Show profiling configuration
	var profilingEndpoints []string
	if s.metrics {
		profilingEndpoints = append(profilingEndpoints, "metrics")
	}
	if s.pprof {
		profilingEndpoints = append(profilingEndpoints, "pprof")
	}
	if s.pyroscope {
		profilingEndpoints = append(profilingEndpoints, "pyroscope")
	}
	if len(profilingEndpoints) > 0 {
		s.printf("  Server endpoints enabled: %v\n", strings.Join(profilingEndpoints, ", "))
	} else {
		s.printf("  Profiling disabled\n")
	}

	s.printf("\n=== Phase 4: Signal Containers ===\n")
	s.printf("  Would find all evt processes in each container\n")
	s.printf("  Would send SIGUSR1 to start triggering simultaneously\n")
	s.printf("  Example: docker exec <container> pkill -USR1 evt\n")

	s.printf("\n=== Phase 5: Monitor & Cleanup ===\n")
	s.printf("  Would monitor container status until completion\n")
	s.printf("  Would collect and display logs\n")
	s.printf("  Would remove containers: docker rm -f <container>...\n")

	return nil
}

func (s *stress) executeFlow() error {
	defer s.cleanup()

	// Check if Tracee is already running before we start
	if s.autoTracee {
		if err := s.checkTraceeNotRunning(); err != nil {
			return err
		}
	}

	s.printf("\n=== Phase 1: Starting Containers ===\n")
	if err := s.startContainers(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}

	s.printf("\n=== Phase 2: Collecting Container IDs ===\n")
	if err := s.collectContainerIDs(); err != nil {
		return fmt.Errorf("failed to collect container IDs: %w", err)
	}

	s.printf("\n=== Phase 3: Configuring & Starting Tracee ===\n")

	if s.autoTracee {
		// Automatically start Tracee
		if err := s.startTracee(); err != nil {
			return fmt.Errorf("failed to start Tracee: %w", err)
		}

		// Tracee startup confirmation already includes proper wait time
		s.printf("Tracee is ready (PID: %d)\n", s.traceePID)
	} else {
		// Manual mode: wait for user
		s.printf("Container scope filter: --scope container=%s\n", strings.Join(s.containerIDs, ","))
		s.printf("\nPlease start Tracee in another terminal with:\n")
		s.printf("  sudo %s --scope container=%s --events ...\n", s.traceeBinary, strings.Join(s.containerIDs, ","))
		s.printf("\nPress ENTER when Tracee is ready to continue...")

		if err := s.waitForUserInput(); err != nil {
			return fmt.Errorf("failed waiting for user input: %w", err)
		}
	}

	// Wait before triggering if requested (for profiling/scraping setup)
	if s.waitBeforeTrigger {
		s.printf("\n=== Waiting Before Triggering ===\n")
		s.printf("Tracee is running and ready for profiling/scraping.\n")

		// Calculate and show expected duration
		if len(s.triggers) > 0 {
			totalOps := 0
			for _, tc := range s.triggers {
				totalOps += int(tc.ops) * tc.instances
			}
			s.printf("\nStress test will generate ~%d events total.\n", totalOps)
			s.printf("Tip: For meaningful profiling, use high ops count and sustained load (30+ seconds).\n")
		}

		// Show available endpoints
		if s.pyroscope {
			s.printf("\nPyroscope profiling is enabled:\n")
			s.printf("  - Start dashboard: make -f builder/Makefile.performance dashboard-start\n")
			s.printf("  - Pyroscope UI will be at: http://localhost:4040/?query=tracee.cpu\n")
			s.printf("  - Grafana dashboard will be at: http://localhost:3000/\n")
			s.printf("  - Or connect external scraper to Tracee's Pyroscope endpoint\n")
		}
		if s.pprof {
			s.printf("\nPprof endpoint: http://localhost:3366/debug/pprof\n")
		}
		if s.metrics {
			s.printf("\nMetrics endpoint: http://localhost:3366/metrics\n")
		}

		s.printf("\nSetup your profiling/scraping tools, then press ENTER to start triggering events...")
		if err := s.waitForUserInput(); err != nil {
			return fmt.Errorf("failed waiting for user input: %w", err)
		}
	}

	s.printf("\n=== Phase 4: Signaling Containers ===\n")
	if err := s.signalContainers(); err != nil {
		return fmt.Errorf("failed to signal containers: %w", err)
	}

	s.printf("\n=== Phase 5: Monitoring ===\n")
	if err := s.monitorContainers(); err != nil {
		return fmt.Errorf("failed to monitor containers: %w", err)
	}

	return nil
}

// startContainers starts one container per trigger type
// Each container will run N parallel instances of evt trigger
func (s *stress) startContainers() error {
	for _, tc := range s.triggers {
		containerName := s.getContainerName(tc.event)

		// Build the command that runs N parallel instances inside the container
		inContainerCmd := s.buildInContainerCommand(tc)

		s.printf("Starting container for trigger: %s\n", tc.event)
		s.printf("  Container name: %s\n", containerName)
		s.printf("  Parallel workers: %d\n", tc.instances)
		s.printf("  Ops per worker: %d\n", tc.ops)
		s.printf("  Sleep: %s\n", tc.sleep)

		// docker run -d --name <name> <image> sh -c "<command>"
		args := []string{
			"run",
			"-d",
			"--name", containerName,
			s.containerImage,
			"sh", "-c",
			inContainerCmd,
		}

		cmd := exec.CommandContext(s.ctx, "docker", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start container %s: %w\nOutput: %s", containerName, err, string(output))
		}

		containerID := strings.TrimSpace(string(output))
		s.printf("  Started container: %s\n", containerID[:12])

		s.mu.Lock()
		s.containerIDs = append(s.containerIDs, containerID)
		s.mu.Unlock()
	}

	return nil
}

// buildInContainerCommand builds the command to run inside the container
// Now uses evt trigger's native --parallel flag instead of spawning multiple processes
// Example output:
// "evt trigger --event foo --ops 100 --sleep 1ms --parallel 3 --wait-signal"
func (s *stress) buildInContainerCommand(tc triggerConfig) string {
	return fmt.Sprintf("evt trigger --event %s --ops %d --sleep %s --parallel %d --wait-signal",
		tc.event, tc.ops, tc.sleep, tc.instances)
}

// collectContainerIDs ensures all container IDs are collected
func (s *stress) collectContainerIDs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.containerIDs) != len(s.triggers) {
		return fmt.Errorf("expected %d containers, got %d", len(s.triggers), len(s.containerIDs))
	}

	s.printf("Collected %d container IDs:\n", len(s.containerIDs))
	for i, id := range s.containerIDs {
		s.printf("  [%d] %s\n", i+1, id[:12])
	}

	return nil
}

// getContainerName generates a consistent container name for a trigger
func (s *stress) getContainerName(trigger string) string {
	return fmt.Sprintf("evt-stress-%s", trigger)
}

// signalContainers sends SIGUSR1 to all evt processes in all containers
func (s *stress) signalContainers() error {
	s.mu.Lock()
	containerIDs := make([]string, len(s.containerIDs))
	copy(containerIDs, s.containerIDs)
	s.mu.Unlock()

	s.printf("Sending SIGUSR1 to start triggering...\n")

	for _, id := range containerIDs {
		// Use pkill to send SIGUSR1 to all evt processes in the container
		// pkill -USR1 evt will signal all processes with "evt" in their name
		cmd := exec.CommandContext(s.ctx, "docker", "exec", id, "pkill", "-USR1", "evt")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to signal container %s: %w", id[:12], err)
		}
		s.printf("  Signaled container: %s\n", id[:12])
	}

	s.printf("All containers signaled successfully\n")
	return nil
}

// monitorContainers waits for all containers to complete
func (s *stress) monitorContainers() error {
	s.mu.Lock()
	containerIDs := make([]string, len(s.containerIDs))
	copy(containerIDs, s.containerIDs)
	s.mu.Unlock()

	s.printf("Monitoring containers until completion...\n")

	// Wait for each container to exit
	for _, id := range containerIDs {
		s.printf("Waiting for container %s to complete...\n", id[:12])

		// docker wait returns the exit code when the container stops
		cmd := exec.CommandContext(s.ctx, "docker", "wait", id)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to wait for container %s: %w", id[:12], err)
		}

		exitCode := strings.TrimSpace(string(output))
		s.printf("  Container %s exited with code: %s\n", id[:12], exitCode)

		// Optionally show logs
		if exitCode != "0" {
			s.printf("  Container logs:\n")
			logsCmd := exec.Command("docker", "logs", "--tail", "20", id)
			logsOutput, _ := logsCmd.CombinedOutput()
			for _, line := range strings.Split(string(logsOutput), "\n") {
				if line != "" {
					s.printf("    %s\n", line)
				}
			}
		}
	}

	s.printf("All containers completed\n")
	return nil
}

// checkTraceeNotRunning verifies no Tracee instance is currently running
func (s *stress) checkTraceeNotRunning() error {
	// Use pgrep to find any running tracee processes
	cmd := exec.Command("pgrep", "-f", "dist/tracee")
	output, err := cmd.Output()

	if err == nil && len(output) > 0 {
		// Found running Tracee processes
		pids := strings.TrimSpace(string(output))
		return fmt.Errorf(
			"Tracee is already running (PID(s): %s)\n"+
				"Please stop the existing Tracee instance(s) before running stress test.\n"+
				"You can stop them with: sudo pkill -TERM tracee",
			pids,
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

// waitForCommand waits for a command to finish
func (s *stress) waitForCommand(cmd *exec.Cmd) <-chan error {
	done := make(chan error, 1)

	go func() {
		done <- cmd.Wait()
		close(done)
	}()

	return done
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

// cleanup removes all created containers and stops Tracee
func (s *stress) cleanup() {
	// Stop Tracee first (unless keepTracee is set)
	if s.autoTracee && !s.keepTracee {
		s.stopTracee()
	} else if s.autoTracee && s.keepTracee {
		s.printf("\n=== Keeping Tracee Running ===\n")
		s.printf("Tracee is still running (PID: %d)\n", s.traceePID)
		s.printf("To stop Tracee later, run: sudo kill -TERM %d\n", s.traceePID)
		if s.pyroscope {
			s.printf("\nPyroscope endpoint is available for profiling.\n")
			s.printf("Pyroscope UI: http://localhost:4040/?query=tracee.cpu\n")
		}
		if s.pprof {
			s.printf("\nPprof endpoint: http://localhost:3366/debug/pprof\n")
		}
		if s.metrics {
			s.printf("\nMetrics endpoint: http://localhost:3366/metrics\n")
			s.printf("Grafana dashboard: http://localhost:3000/\n")
		}
	}

	s.mu.Lock()
	containerIDs := make([]string, len(s.containerIDs))
	copy(containerIDs, s.containerIDs)
	s.mu.Unlock()

	if len(containerIDs) == 0 {
		return
	}

	s.printf("\n=== Cleanup: Removing Containers ===\n")
	for _, id := range containerIDs {
		s.printf("Removing container: %s\n", id[:12])
		cmd := exec.Command("docker", "rm", "-f", id)
		if err := cmd.Run(); err != nil {
			s.printErrf("Failed to remove container %s: %v\n", id[:12], err)
		}
	}
}

func (s *stress) printf(format string, args ...interface{}) {
	s.cmd.Printf(format, args...)
}

func (s *stress) println(args ...interface{}) {
	s.cmd.Println(args...)
}

func (s *stress) printErrf(format string, args ...interface{}) {
	s.cmd.PrintErrf(format, args...)
}

func (s *stress) printErrln(args ...interface{}) {
	s.cmd.PrintErrln(args...)
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

// Helper functions

// getContainerID gets the container ID by name
func getContainerID(ctx context.Context, containerName string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-aqf", fmt.Sprintf("name=%s", containerName))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get container ID: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
