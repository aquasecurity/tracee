package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func Test_E2E_BasicEventCapture(t *testing.T) {
	t.Parallel()
	assureIsRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create event buffer
	eventBuffer := newEventBuffer()

	// Configure Tracee
	cfg := config.Config{}

	// Create and configure policy
	pol := policy.NewPolicy()
	pol.ID = 0
	pol.Name = "test-policy"

	// Enable specific events
	eventsToTrace := []events.ID{
		events.Execve,
		events.Open,
		events.Write,
		events.SecurityFileOpen,
	}

	for _, evt := range eventsToTrace {
		pol.Rules[evt] = policy.RuleData{
			EventID: evt,
		}
	}

	cfg.InitialPolicies = []interface{}{pol}

	// Start Tracee
	traceeInstance, err := startTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = waitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Subscribe to events
	eventStream := traceeInstance.SubscribeAll()
	defer traceeInstance.Unsubscribe(eventStream)

	// Start event collection goroutine
	go func() {
		for {
			select {
			case event := <-eventStream.Read():
				if event != nil {
					eventBuffer.addEvent(*event)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Test Case 1: Execute a command
	cmd := exec.Command("ls", "/tmp")
	err = cmd.Run()
	require.NoError(t, err, "Failed to execute test command")

	// Test Case 2: Write to a file
	testFile := filepath.Join(os.TempDir(), "tracee_test_file")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err, "Failed to write test file")
	defer os.Remove(testFile)

	// Wait for events
	err = waitForTraceeOutputEvents(t, 5*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify events
	events := eventBuffer.getCopy()
	assert.Greater(t, len(events), 0, "No events captured")

	foundExecve := false
	foundOpen := false
	foundWrite := false

	for _, evt := range events {
		switch evt.EventID {
		case int(events.Execve):
			foundExecve = true
			// Verify execve event details
			for _, arg := range evt.Args {
				if arg.Name == "pathname" {
					assert.Contains(t, arg.Value.(string), "ls", "Unexpected command in execve event")
				}
			}
		case int(events.Open):
			foundOpen = true
			// Verify open event details
			for _, arg := range evt.Args {
				if arg.Name == "pathname" {
					assert.Contains(t, arg.Value.(string), "tracee_test_file", "Unexpected file in open event")
				}
			}
		case int(events.Write):
			foundWrite = true
			// Verify write event details
			for _, arg := range evt.Args {
				if arg.Name == "bytes_count" {
					assert.Greater(t, arg.Value.(int64), int64(0), "Write event with zero bytes")
				}
			}
		}
	}

	assert.True(t, foundExecve, "No execve event found")
	assert.True(t, foundOpen, "No open event found")
	assert.True(t, foundWrite, "No write event found")
}

func Test_E2E_ContainerEvents(t *testing.T) {
	t.Parallel()
	assureIsRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create event buffer
	eventBuffer := newEventBuffer()

	// Configure Tracee
	cfg := config.Config{}

	// Create and configure policy
	pol := policy.NewPolicy()
	pol.ID = 0
	pol.Name = "container-policy"

	// Enable container events
	containerEvents := []events.ID{
		events.ContainerCreate,
		events.ContainerRemove,
		events.ContainerStart,
		events.ContainerStop,
	}

	for _, evt := range containerEvents {
		pol.Rules[evt] = policy.RuleData{
			EventID: evt,
		}
	}

	cfg.InitialPolicies = []interface{}{pol}

	// Start Tracee
	traceeInstance, err := startTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = waitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Subscribe to events
	eventStream := traceeInstance.SubscribeAll()
	defer traceeInstance.Unsubscribe(eventStream)

	// Start event collection goroutine
	go func() {
		for {
			select {
			case event := <-eventStream.Read():
				if event != nil {
					eventBuffer.addEvent(*event)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Run a test container
	containerName := "tracee-test-container"
	runCmd := exec.Command("docker", "run", "--name", containerName, "-d", "alpine", "sleep", "5")
	err = runCmd.Run()
	require.NoError(t, err, "Failed to start test container")

	// Wait for container to finish and remove it
	time.Sleep(6 * time.Second)
	removeCmd := exec.Command("docker", "rm", "-f", containerName)
	_ = removeCmd.Run()

	// Wait for events
	err = waitForTraceeOutputEvents(t, 10*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify container events
	events := eventBuffer.getCopy()
	assert.Greater(t, len(events), 0, "No container events captured")

	foundCreate := false
	foundStart := false
	foundStop := false
	foundRemove := false

	for _, evt := range events {
		switch evt.EventID {
		case int(events.ContainerCreate):
			foundCreate = true
			assert.Contains(t, evt.Container.Name, containerName)
		case int(events.ContainerStart):
			foundStart = true
			assert.Contains(t, evt.Container.Name, containerName)
		case int(events.ContainerStop):
			foundStop = true
			assert.Contains(t, evt.Container.Name, containerName)
		case int(events.ContainerRemove):
			foundRemove = true
			assert.Contains(t, evt.Container.Name, containerName)
		}
	}

	assert.True(t, foundCreate, "No container_create event found")
	assert.True(t, foundStart, "No container_start event found")
	assert.True(t, foundStop, "No container_stop event found")
	assert.True(t, foundRemove, "No container_remove event found")
}

func Test_E2E_EdgeCases(t *testing.T) {
	t.Parallel()
	assureIsRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create event buffer
	eventBuffer := newEventBuffer()

	// Configure Tracee
	cfg := config.Config{}

	// Create and configure policy
	pol := policy.NewPolicy()
	pol.ID = 0
	pol.Name = "edge-case-policy"

	// Enable specific events
	eventsToTrace := []events.ID{
		events.Execve,
		events.SecurityFileOpen,
		events.Ptrace,
		events.Mmap,
		events.Mprotect,
	}

	for _, evt := range eventsToTrace {
		pol.Rules[evt] = policy.RuleData{
			EventID: evt,
		}
	}

	cfg.InitialPolicies = []interface{}{pol}

	// Start Tracee
	traceeInstance, err := startTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = waitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Subscribe to events
	eventStream := traceeInstance.SubscribeAll()
	defer traceeInstance.Unsubscribe(eventStream)

	// Start event collection goroutine
	go func() {
		for {
			select {
			case event := <-eventStream.Read():
				if event != nil {
					eventBuffer.addEvent(*event)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Test Case 1: Execute non-existent command
	cmd := exec.Command("/nonexistent/binary")
	_ = cmd.Run() // Expected to fail

	// Test Case 2: Create and execute file with special characters
	specialFileName := "test!@#$%^&*()"
	specialFilePath := filepath.Join(os.TempDir(), specialFileName)
	err = os.WriteFile(specialFilePath, []byte("#!/bin/sh\necho test"), 0755)
	require.NoError(t, err, "Failed to create special file")
	defer os.Remove(specialFilePath)

	cmd = exec.Command(specialFilePath)
	err = cmd.Run()
	require.NoError(t, err, "Failed to execute special file")

	// Test Case 3: Rapid file operations
	for i := 0; i < 100; i++ {
		tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("tracee_test_%d", i))
		_ = os.WriteFile(tempFile, []byte("test"), 0644)
		_ = os.Remove(tempFile)
	}

	// Wait for events
	err = waitForTraceeOutputEvents(t, 5*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify events
	events := eventBuffer.getCopy()
	assert.Greater(t, len(events), 0, "No events captured")

	// Verify handling of non-existent binary
	foundNonexistentExec := false
	for _, evt := range events {
		if evt.EventID == int(events.Execve) {
			for _, arg := range evt.Args {
				if arg.Name == "pathname" && strings.Contains(arg.Value.(string), "/nonexistent/binary") {
					foundNonexistentExec = true
					// Verify error handling
					assert.NotEqual(t, evt.ReturnValue, 0, "Execve of non-existent binary should fail")
				}
			}
		}
	}
	assert.True(t, foundNonexistentExec, "No event for non-existent binary execution attempt")

	// Verify handling of special characters
	foundSpecialFile := false
	for _, evt := range events {
		if evt.EventID == int(events.Execve) {
			for _, arg := range evt.Args {
				if arg.Name == "pathname" && strings.Contains(arg.Value.(string), specialFileName) {
					foundSpecialFile = true
					// Verify successful execution
					assert.Equal(t, evt.ReturnValue, 0, "Execve of special file should succeed")
				}
			}
		}
	}
	assert.True(t, foundSpecialFile, "No event for special file execution")

	// Verify rapid file operations
	var openCount, writeCount int
	for _, evt := range events {
		if evt.EventID == int(events.SecurityFileOpen) && strings.Contains(evt.Args[0].Value.(string), "tracee_test_") {
			openCount++
		}
		if evt.EventID == int(events.Write) && strings.Contains(evt.Args[0].Value.(string), "tracee_test_") {
			writeCount++
		}
	}
	assert.Greater(t, openCount, 0, "No file open events captured for rapid operations")
	assert.Greater(t, writeCount, 0, "No write events captured for rapid operations")
}

func Test_E2E_ResourceExhaustion(t *testing.T) {
	t.Parallel()
	assureIsRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create event buffer
	eventBuffer := newEventBuffer()

	// Configure Tracee with minimal buffer sizes
	cfg := config.Config{
		PerfBufferSize:     1, // Minimal perf buffer size
		BlobPerfBufferSize: 1, // Minimal blob buffer size
	}

	// Create and configure policy
	pol := policy.NewPolicy()
	pol.ID = 0
	pol.Name = "resource-test-policy"

	// Enable high-frequency events
	eventsToTrace := []events.ID{
		events.SchedProcessExec,
		events.SchedProcessExit,
		events.SchedProcessFork,
		events.Write,
		events.Read,
	}

	for _, evt := range eventsToTrace {
		pol.Rules[evt] = policy.RuleData{
			EventID: evt,
		}
	}

	cfg.InitialPolicies = []interface{}{pol}

	// Start Tracee
	traceeInstance, err := startTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = waitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Subscribe to events
	eventStream := traceeInstance.SubscribeAll()
	defer traceeInstance.Unsubscribe(eventStream)

	// Start event collection goroutine
	go func() {
		for {
			select {
			case event := <-eventStream.Read():
				if event != nil {
					eventBuffer.addEvent(*event)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Generate high load of events
	for i := 0; i < 1000; i++ {
		cmd := exec.Command("echo", "test")
		_ = cmd.Run()
	}

	// Wait for events
	err = waitForTraceeOutputEvents(t, 5*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify events
	events := eventBuffer.getCopy()
	assert.Greater(t, len(events), 0, "No events captured")

	// Check for lost events indicator
	var lostEvents int
	for _, evt := range events {
		if evt.EventName == "lost_events" {
			lostEvents++
		}
	}

	// We expect some lost events due to small buffer sizes
	t.Logf("Lost events count: %d", lostEvents)
}
