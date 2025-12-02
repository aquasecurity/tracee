package stress

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
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
	traceeBinary       string
	traceeOutput       string
	autoTracee         bool
	eventNames         []string      // Event names to pass to Tracee
	metrics            bool          // Enable metrics collection
	pprof              bool          // Enable pprof profiling
	pyroscope          bool          // Enable pyroscope profiling
	keepTracee         bool          // Keep Tracee running after stress test
	waitBeforeTrigger  bool          // Wait for user input before triggering events
	signalTimeout      time.Duration // Timeout for containers waiting for signal
	traceeInitCooldown time.Duration // Cooldown after Tracee starts
	stressEndCooldown  time.Duration // Cooldown after stress completes

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
		s.printf("    docker container run -d --name %s --privileged --cap-add=ALL \\\n", containerName)
		s.printf("      --security-opt seccomp=unconfined --security-opt apparmor=unconfined \\\n")
		s.printf("      %s %s\n", s.containerImage, inContainerCmd)
		s.printf("  Container privileges:\n")
		s.printf("    - Full system privileges (--privileged, --cap-add=ALL)\n")
		s.printf("    - No syscall/security restrictions (unrestricted access)\n")
		s.printf("    - Full CPU and memory access (no limits)\n")
		s.printf("  In-container command breakdown:\n")
		s.printf("    - Runs single evt trigger process with %d parallel workers\n", tc.instances)
		s.printf("    - Command: %s\n", inContainerCmd)
		s.printf("    - Waits for SIGUSR1 before starting (timeout: %s)\n", s.signalTimeout)
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
	if len(s.triggers) > 0 {
		totalOps := 0
		for _, tc := range s.triggers {
			totalOps += int(tc.ops) * tc.instances
		}
		s.printf("  Would execute ~%d trigger operations total\n", totalOps)
		s.printf("  Note: Actual event count depends on what each trigger does (may be higher)\n")
	}
	s.printf("  Would find all evt processes in each container\n")
	s.printf("  Would send SIGUSR1 to start triggering simultaneously\n")
	s.printf("  Example: docker container exec <container> pkill -USR1 evt\n")

	s.printf("\n=== Phase 5: Monitor & Cleanup ===\n")
	s.printf("  Would monitor container status until completion\n")
	s.printf("  Would collect and display logs\n")
	s.printf("  Would remove containers: docker container rm -f <container>...\n")

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
		s.mu.Lock()
		pid := s.traceePID
		s.mu.Unlock()
		s.printf("Tracee is ready (PID: %d)\n", pid)
	} else {
		// Manual mode: wait for user
		s.mu.Lock()
		containerIDs := make([]string, len(s.containerIDs))
		copy(containerIDs, s.containerIDs)
		s.mu.Unlock()

		containerScope := strings.Join(containerIDs, ",")
		s.printf("Container scope filter: --scope container=%s\n", containerScope)
		s.printf("\nPlease start Tracee in another terminal with:\n")
		s.printf("  sudo %s --scope container=%s --events ...\n", s.traceeBinary, containerScope)
		s.printf("\nPress ENTER when Tracee is ready to continue...")

		if err := s.waitForUserInput(); err != nil {
			return fmt.Errorf("failed waiting for user input: %w", err)
		}
	}

	// Wait before triggering if requested (for profiling/scraping setup)
	if s.waitBeforeTrigger {
		s.printf("\n=== Waiting Before Triggering ===\n")
		s.printf("Tracee is running and ready for profiling/scraping.\n")

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

	// Show what's about to be executed
	if len(s.triggers) > 0 {
		totalOps := 0
		for _, tc := range s.triggers {
			totalOps += int(tc.ops) * tc.instances
		}
		s.printf("About to execute ~%d trigger operations total.\n", totalOps)
		s.printf("Note: Actual event count depends on what each trigger does (may be higher).\n")
	}

	if err := s.signalContainers(); err != nil {
		return fmt.Errorf("failed to signal containers: %w", err)
	}

	s.printf("\n=== Phase 5: Monitoring ===\n")
	if err := s.monitorContainers(); err != nil {
		return fmt.Errorf("failed to monitor containers: %w", err)
	}

	// Cooldown period after stress completes (before cleanup)
	// Allows system to stabilize and Tracee to finish processing
	// Skip if context was cancelled (e.g., Ctrl+C)
	if s.stressEndCooldown > 0 {
		s.printf("\n=== Stress End Cooldown ===\n")
		s.printf("Waiting %v for system stabilization...\n", s.stressEndCooldown)
		select {
		case <-time.After(s.stressEndCooldown):
			// Cooldown complete
		case <-s.ctx.Done():
			// Context cancelled during cooldown
			s.printf("Cooldown interrupted\n")
			return s.ctx.Err()
		}
	}

	return nil
}

// cleanup removes all created containers and stops Tracee
// Tracee cleanup behavior:
//
//	auto-tracee=true  + keep-tracee=false (default) → Stop tracee automatically
//	auto-tracee=true  + keep-tracee=true            → Keep tracee running (user stops it)
//	auto-tracee=false + keep-tracee=*               → No action (user manages tracee)
func (s *stress) cleanup() {
	// Stop Tracee first (unless keepTracee is set)
	if s.autoTracee && !s.keepTracee {
		if err := s.stopTracee(); err != nil {
			// Don't warn about context cancellation - it's expected during Ctrl+C
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.printErrf("Warning: failed to stop Tracee: %v\n", err)
			}
		}
	} else if s.autoTracee && s.keepTracee {
		s.mu.Lock()
		pid := s.traceePID
		s.mu.Unlock()

		s.printf("\n=== Keeping Tracee Running (--keep-tracee) ===\n")
		s.printf("Tracee is still running (PID: %d)\n", pid)
		s.printf("To stop Tracee later, run: sudo kill -TERM %d\n", pid)
	} else if !s.autoTracee {
		s.printf("\n=== Tracee Management (--auto-tracee=false) ===\n")
		s.printf("Tracee was manually started by you.\n")
		s.printf("You are responsible for stopping it when done.\n")
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
		cmd := exec.Command("docker", "container", "rm", "-f", id)
		if err := cmd.Run(); err != nil {
			s.printErrf("Failed to remove container %s: %v\n", id[:12], err)
		}
	}
}
