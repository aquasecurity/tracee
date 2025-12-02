package stress

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

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
		s.printf("  Privileges: full (--privileged, no resource limits)\n")

		// docker container run with full privileges and resources
		// Run containers with same privileges as the user (if sudo, they get root privileges)
		// No CPU/memory limits - full system access for realistic stress testing
		args := []string{
			"container",
			"run",
			"-d",
			"--name", containerName,
			"--privileged",                         // Full container privileges
			"--cap-add=ALL",                        // All Linux capabilities
			"--security-opt", "seccomp=unconfined", // No syscall restrictions
			"--security-opt", "apparmor=unconfined", // No AppArmor restrictions
			// No CPU/memory limits - containers get full access
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

		// Give container a moment to start, then check if it's still running
		time.Sleep(500 * time.Millisecond)
		checkCmd := exec.CommandContext(s.ctx, "docker", "container", "ls", "-q", "-f", fmt.Sprintf("id=%s", containerID))
		checkOut, _ := checkCmd.Output()
		if len(strings.TrimSpace(string(checkOut))) == 0 {
			// Container already exited - get logs
			logsCmd := exec.CommandContext(s.ctx, "docker", "container", "logs", containerID)
			logs, _ := logsCmd.Output()
			return fmt.Errorf("container %s exited immediately after start.\nLogs:\n%s", containerID[:12], string(logs))
		}
		s.printf("  Container is running and waiting for signal\n")
	}

	return nil
}

// buildInContainerCommand builds the command to run inside the container
// Now uses evt trigger's native --parallel flag instead of spawning multiple processes
// Example output:
// "evt trigger --event foo --ops 100 --sleep 1ms --parallel 3 --wait-signal --signal-timeout 15m"
func (s *stress) buildInContainerCommand(tc triggerConfig) string {
	return fmt.Sprintf("evt trigger --event %s --ops %d --sleep %s --parallel %d --wait-signal --signal-timeout %s",
		tc.event, tc.ops, tc.sleep, tc.instances, s.signalTimeout)
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
		// First, check if container is still running
		checkCmd := exec.CommandContext(s.ctx, "docker", "container", "ls", "-q", "-f", fmt.Sprintf("id=%s", id))
		output, err := checkCmd.Output()
		if err != nil || len(strings.TrimSpace(string(output))) == 0 {
			// Container not running - get logs to see what happened
			logsCmd := exec.CommandContext(s.ctx, "docker", "container", "logs", id)
			logs, _ := logsCmd.Output()
			return fmt.Errorf(
				"container %s is not running (may have crashed or timed out)\n"+
					"Container logs:\n%s",
				id[:12], string(logs))
		}

		// Use pkill to send SIGUSR1 to all evt processes in the container
		// pkill -USR1 evt will signal all processes with "evt" in their name
		cmd := exec.CommandContext(s.ctx, "docker", "container", "exec", id, "pkill", "-USR1", "evt")
		if err := cmd.Run(); err != nil {
			// pkill returns exit 1 if no processes found - get container logs for debugging
			logsCmd := exec.CommandContext(s.ctx, "docker", "container", "logs", id)
			logs, _ := logsCmd.Output()
			return fmt.Errorf(
				"failed to signal container %s: %w\n"+
					"No 'evt' processes found in container.\n"+
					"Container logs:\n%s",
				id[:12], err, string(logs))
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

	s.printf("Waiting for %d containers to complete...\n", len(containerIDs))
	s.printf("(Press Ctrl+C to stop monitoring and clean up)\n\n")

	// Wait for each container to exit
	for i, id := range containerIDs {
		// docker container wait returns the exit code when the container stops
		cmd := exec.CommandContext(s.ctx, "docker", "container", "wait", id)
		output, err := cmd.Output()
		if err != nil {
			// If context was canceled (user pressed Ctrl+C), the docker command is killed
			// This is expected - containers are still running and will be cleaned up
			if s.ctx.Err() == context.Canceled {
				s.printf("\nMonitoring interrupted (containers will be cleaned up)\n")
				return nil
			}
			return fmt.Errorf("failed to wait for container %s: %w", id[:12], err)
		}

		exitCode := strings.TrimSpace(string(output))
		s.printf("[%d/%d] Container %s completed with exit code: %s\n", i+1, len(containerIDs), id[:12], exitCode)

		// Optionally show logs
		if exitCode != "0" {
			s.printf("  Container logs:\n")
			logsCmd := exec.Command("docker", "container", "logs", "--tail", "20", id)
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
