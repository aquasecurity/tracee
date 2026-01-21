package integration

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// Test_ContainerCreateRemove tests that ContainerCreate and ContainerRemove events
// are properly derived from cgroup_mkdir and cgroup_rmdir events
func Test_ContainerCreateRemove(t *testing.T) {
	defer goleak.VerifyNone(t)

	testutils.AssureIsRoot(t)

	containerName := "tracee-test-container"
	cleanupContainer := func() {
		cmd := exec.Command("docker", "rm", "-f", containerName)
		_ = cmd.Run()
	}

	// Clean up any leftover container from previous failed test runs
	cleanupContainer()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Start by pulling the busybox image
	pullCmd := exec.Command("docker", "pull", busyboxImage)
	err := pullCmd.Run()
	require.NoError(t, err, "Failed to pull busybox image")

	// Create event buffer
	eventBuffer := testutils.NewEventBuffer()

	// Configure Tracee
	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		Enrichment: &config.EnrichmentConfig{
			Container: config.ContainerEnrichmentConfig{
				Enabled: true, // Enable container enrichment for this test
			},
			Sockets: runtime.Sockets{},
		},
	}

	// Register docker socket for the test
	cfg.Enrichment.Sockets.Register(runtime.Docker, "/var/run/docker.sock")

	// Enable container events (derived events from cgroup operations)
	containerEvents := []events.ID{
		events.ContainerCreate, // Derived from cgroup_mkdir
		events.ContainerRemove, // Derived from cgroup_rmdir
	}

	// Create policies using testutils to ensure proper initialization
	policies := testutils.BuildPoliciesFromEvents(containerEvents)
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}
	cfg.InitialPolicies = initialPolicies

	// Start Tracee
	t.Log("  --- started tracee ---")
	traceeInstance, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	// Ensure cleanup happens even if test fails early (prevents goroutine leaks)
	defer func() {
		cleanupContainer()
		cancel()
		if err := testutils.WaitForTraceeStop(traceeInstance); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		} else {
			t.Log("  --- stopped tracee ---")
		}
	}()

	err = testutils.WaitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Subscribe to events
	eventStream, err := traceeInstance.Subscribe(config.Stream{})
	require.NoError(t, err)
	defer traceeInstance.Unsubscribe(eventStream)

	// Start event collection goroutine
	go func() {
		for {
			select {
			case pbEvent := <-eventStream.ReceiveEvents():
				if pbEvent != nil {
					eventBuffer.AddEvent(pbEvent)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Run a test container
	runCmd := exec.Command("docker", "run", "--name", containerName, "-d", busyboxImage, "sleep", "5")
	err = runCmd.Run()
	require.NoError(t, err, "Failed to start test container")

	// Wait for container to finish and remove it
	time.Sleep(6 * time.Second)
	cleanupContainer()

	// Wait for events
	err = testutils.WaitForTraceeOutputEvents(t, 10*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify container events
	capturedEvents := eventBuffer.GetCopy()
	assert.Greater(t, len(capturedEvents), 0, "No container events captured")

	foundCreate := false
	foundRemove := false

	for _, evt := range capturedEvents {
		eventID := events.ID(evt.Id)
		switch eventID {
		case events.ContainerCreate:
			foundCreate = true
			t.Log("Found ContainerCreate event")
			// Verify it has container-related arguments
			assert.NotEmpty(t, evt.Data, "ContainerCreate should have arguments")

			// Check for expected fields: runtime, container_id, container_name, etc.
			hasRuntime := false
			hasContainerID := false
			hasContainerName := false

			for _, arg := range evt.Data {
				switch arg.Name {
				case "runtime":
					hasRuntime = true
					t.Logf("  Runtime: %v", arg.GetStr())
				case "container_id":
					hasContainerID = true
					t.Logf("  Container ID: %v", arg.GetStr())
				case "container_name":
					hasContainerName = true
					containerNameVal := arg.GetStr()
					// Container name may be empty due to enrichment concurrency issue
					// See: https://github.com/aquasecurity/tracee/issues/3850
					// The container_create event can be derived before enrichment completes
					if containerNameVal != "" {
						assert.Equal(t, containerName, containerNameVal,
							"Container name should match test container name when populated")
						t.Logf("  ✅ Container Name: %s", containerNameVal)
					} else {
						t.Log("  ⚠️  Container name not populated (enrichment issue #3850)")
					}
				}
			}

			assert.True(t, hasRuntime, "ContainerCreate should have 'runtime' field")
			assert.True(t, hasContainerID, "ContainerCreate should have 'container_id' field")
			assert.True(t, hasContainerName, "ContainerCreate should have 'container_name' field")

		case events.ContainerRemove:
			foundRemove = true
			t.Log("Found ContainerRemove event")
			// Verify it has the expected fields
			assert.NotEmpty(t, evt.Data, "ContainerRemove should have arguments")

			hasRuntime := false
			hasContainerID := false

			for _, arg := range evt.Data {
				switch arg.Name {
				case "runtime":
					hasRuntime = true
					t.Logf("  Runtime: %v", arg.GetStr())
				case "container_id":
					hasContainerID = true
					t.Logf("  Container ID: %v", arg.GetStr())
				}
			}

			assert.True(t, hasRuntime, "ContainerRemove should have 'runtime' field")
			assert.True(t, hasContainerID, "ContainerRemove should have 'container_id' field")
		}
	}

	// Both events should be present - derived from cgroup_mkdir and cgroup_rmdir
	assert.True(t, foundCreate, "ContainerCreate (derived) event should be captured")
	assert.True(t, foundRemove, "ContainerRemove (derived) event should be captured")
}

// Test_ExistingContainers tests that ExistingContainer events are emitted
// for containers that were already running when Tracee started
func Test_ExistingContainers(t *testing.T) {
	defer goleak.VerifyNone(t)

	testutils.AssureIsRoot(t)

	// Start by pulling the busybox image
	pullCmd := exec.Command("docker", "pull", busyboxImage)
	err := pullCmd.Run()
	require.NoError(t, err, "Failed to pull busybox image")

	// First, start a container before starting Tracee
	testContainerName := "tracee-existing-container"

	// Clean up any previous container with the same name
	cleanupCmd := exec.Command("docker", "rm", "-f", testContainerName)
	_ = cleanupCmd.Run()

	// Start a long-running container
	startCmd := exec.Command("docker", "run", "--name", testContainerName, "-d", busyboxImage, "sleep", "60")
	err = startCmd.Run()
	require.NoError(t, err, "Failed to start existing container")

	// Ensure container cleanup at the end
	defer func() {
		removeCmd := exec.Command("docker", "rm", "-f", testContainerName)
		_ = removeCmd.Run()
	}()

	// Wait a bit to ensure container is fully started
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Create event buffer
	eventBuffer := testutils.NewEventBuffer()

	// Configure Tracee
	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		Enrichment: &config.EnrichmentConfig{
			Container: config.ContainerEnrichmentConfig{
				Enabled: true, // Enable container enrichment for this test
			},
			Sockets: runtime.Sockets{},
		},
	}

	// Register docker socket for the test
	cfg.Enrichment.Sockets.Register(runtime.Docker, "/var/run/docker.sock")

	// Enable ExistingContainer event
	existingContainerEvents := []events.ID{
		events.ExistingContainer,
	}

	// Create policies using testutils to ensure proper initialization
	policies := testutils.BuildPoliciesFromEvents(existingContainerEvents)
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}
	cfg.InitialPolicies = initialPolicies

	// Start Tracee AFTER the container is already running
	t.Log("  --- started tracee ---")
	traceeInstance, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	// Ensure Tracee cleanup happens even if test fails early (prevents goroutine leaks)
	defer func() {
		cancel()
		if err := testutils.WaitForTraceeStop(traceeInstance); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		} else {
			t.Log("  --- stopped tracee ---")
		}
	}()

	// Subscribe to events BEFORE waiting for Tracee to start
	// (ExistingContainer events are emitted during Tracee's initialization)
	eventStream, err := traceeInstance.Subscribe(config.Stream{})
	require.NoError(t, err)
	defer traceeInstance.Unsubscribe(eventStream)
	// Start event collection goroutine
	go func() {
		for {
			select {
			case pbEvent := <-eventStream.ReceiveEvents():
				if pbEvent != nil {
					eventBuffer.AddEvent(pbEvent)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	err = testutils.WaitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	// Wait for events to be captured (ExistingContainer events are emitted during startup)
	time.Sleep(3 * time.Second)

	// Wait for at least one event
	err = testutils.WaitForTraceeOutputEvents(t, 10*time.Second, eventBuffer, 1, true)
	require.NoError(t, err, "Failed waiting for events")

	// Verify ExistingContainer event
	capturedEvents := eventBuffer.GetCopy()
	assert.Greater(t, len(capturedEvents), 0, "No events captured")

	foundExisting := false
	var testContainerEvent *pb.Event

	for _, evt := range capturedEvents {
		eventID := events.ID(evt.Id)
		if eventID == events.ExistingContainer {
			foundExisting = true
			t.Log("Found ExistingContainer event")

			// Verify it has container-related arguments
			assert.NotEmpty(t, evt.Data, "ExistingContainer should have arguments")

			// Get the container name
			var containerName string
			for _, arg := range evt.Data {
				if arg.Name == "container_name" {
					containerName = arg.GetStr()
					break
				}
			}
			if containerName == "" {
				t.Log("Failed to get container name")
				continue
			}
			if containerName != testContainerName {
				continue
			}
			testContainerEvent = evt
			break
		}
	}
	assert.True(t, foundExisting, "ExistingContainer event should be emitted for pre-existing containers")
	assert.NotNil(t, testContainerEvent, "Test container not found")

	if testContainerEvent != nil {
		// Check for expected fields
		hasRuntime := false
		hasContainerID := false
		hasContainerName := false

		for _, arg := range testContainerEvent.Data {
			switch arg.Name {
			case "runtime":
				hasRuntime = true
				t.Logf("  Runtime: %v", arg.GetStr())
			case "container_id":
				hasContainerID = true
				t.Logf("  Container ID: %v", arg.GetStr())
			case "container_name":
				hasContainerName = true
				containerNameVal := arg.GetStr()
				assert.True(t, containerNameVal == testContainerName,
					"Container name should contain test container name")
				t.Logf("  Container Name: %v", arg.Value)
			case "container_image":
				t.Logf("  Container Image: %v", arg.Value)
			}
		}

		assert.True(t, hasRuntime, "ExistingContainer should have 'runtime' field")
		assert.True(t, hasContainerID, "ExistingContainer should have 'container_id' field")
		assert.True(t, hasContainerName, "ExistingContainer should have 'container_name' field")
	}
}
