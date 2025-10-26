package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	// processTerminationWait is the time to wait for processes to terminate after SIGTERM
	processTerminationWait = 200 * time.Millisecond
	// serviceStopWait is the time to wait for systemd service to stop
	serviceStopWait = 500 * time.Millisecond
)

// TestMain provides setup and teardown for all integration tests
func TestMain(m *testing.M) {
	// Setup: Stop unattended-upgrades to prevent interference with tests
	if err := stopUnattendedUpgrades(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to stop unattended-upgrades: %v\n", err)
		// Don't fail the tests, just warn - the service may not be installed
	}

	// Run tests
	m.Run()

	// Cleanup (if needed) would go here
}

// stopUnattendedUpgrades stops the unattended-upgrades service and any running processes
func stopUnattendedUpgrades() error {
	// Check if running as root (required for systemctl and pkill)
	if os.Geteuid() != 0 {
		return errors.New("not running as root, cannot stop unattended-upgrades")
	}

	// First, check if unattended-upgrades is even installed
	if _, err := exec.LookPath("unattended-upgrades"); err != nil {
		// Not installed, nothing to do
		return nil
	}

	fmt.Println("Stopping unattended-upgrades service to prevent test interference...")

	// Stop the systemd service
	stopCmd := exec.Command("systemctl", "stop", "unattended-upgrades")
	if err := stopCmd.Run(); err != nil {
		// Service might not exist or might already be stopped - not critical
		fmt.Printf("Note: systemctl stop failed (may not be an error): %v\n", err)
	}

	// Kill any currently running unattended-upgrades processes
	if err := killUnattendedUpgrades(); err != nil {
		fmt.Printf("Note: Failed to kill unattended-upgrades processes: %v\n", err)
	}

	// Wait for processes to terminate
	time.Sleep(serviceStopWait)

	fmt.Println("unattended-upgrades stopped successfully")
	return nil
}

// killUnattendedUpgrades kills any running unattended-upgrades processes
func killUnattendedUpgrades() error {
	// Check if there are any running processes
	checkCmd := exec.Command("pgrep", "-f", "unattended-upgrades")
	if err := checkCmd.Run(); err != nil {
		// No processes found (pgrep returns non-zero if no matches)
		return nil
	}

	// Try graceful termination first (SIGTERM)
	killCmd := exec.Command("pkill", "-TERM", "-f", "unattended-upgrades")
	_ = killCmd.Run() // Ignore error - might already be dead

	// Wait for graceful termination
	time.Sleep(processTerminationWait)

	// Check if still running
	checkCmd = exec.Command("pgrep", "-f", "unattended-upgrades")
	if err := checkCmd.Run(); err != nil {
		// No processes found, we're done
		return nil
	}

	// Force kill if still running (SIGKILL)
	forceKillCmd := exec.Command("pkill", "-KILL", "-f", "unattended-upgrades")
	return forceKillCmd.Run()
}
