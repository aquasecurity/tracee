package container

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

// TestManager_DataStoreInterface tests the DataStore interface implementation.
// Note: Full Manager initialization requires runtime dependencies (cgroups, sockets, etc.)
// so we use a minimal setup that just tests the interface is correctly implemented.
func TestManager_DataStoreInterface(t *testing.T) {
	// Create a minimal Manager for testing the interface
	mgr := &Manager{
		containerMap: make(map[string]Container),
	}

	t.Run("Name", func(t *testing.T) {
		name := mgr.Name()
		assert.Equal(t, "container", name)
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := mgr.GetHealth()
		assert.NotNil(t, health)
		// Should not panic and return a valid health status
		assert.Contains(t, []datastores.HealthStatus{
			datastores.HealthHealthy,
			datastores.HealthUnhealthy,
		}, health.Status)
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := mgr.GetMetrics()
		assert.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.ItemCount, int64(0))
	})

	t.Run("GetContainer_NotFound", func(t *testing.T) {
		info, err := mgr.GetContainer("nonexistent")
		assert.ErrorIs(t, err, datastores.ErrNotFound)
		assert.Nil(t, info)
	})

	t.Run("GetContainerByName_NotFound", func(t *testing.T) {
		info, err := mgr.GetContainerByName("nonexistent")
		assert.ErrorIs(t, err, datastores.ErrNotFound)
		assert.Nil(t, info)
	})
}

func TestManager_ListContainers(t *testing.T) {
	t.Run("NoFilter_EmptyResult", func(t *testing.T) {
		mgr := &Manager{
			containerMap: make(map[string]Container),
			cgroupsMap:   make(map[uint32]CgroupDir),
		}

		containers, err := mgr.ListContainers()
		require.NoError(t, err)
		assert.Empty(t, containers)
	})

	t.Run("NoFilter_SingleContainer", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {
					ContainerId: "container1",
					Name:        "test-container",
					Image:       "nginx:latest",
					Runtime:     runtime.Docker,
					CreatedAt:   time.Now(),
				},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {
					ContainerId:   "container1",
					ContainerRoot: true,
					expiresAt:     time.Time{}, // Zero time = not expired
				},
			},
		}

		containers, err := mgr.ListContainers(nil)
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "container1", containers[0].ID)
		assert.Equal(t, "test-container", containers[0].Name)
		assert.Equal(t, "nginx:latest", containers[0].Image)
		assert.Equal(t, "docker", containers[0].Runtime)
	})

	t.Run("NoFilter_MultipleContainers", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {
					ContainerId: "container1",
					Name:        "nginx-container",
					Image:       "nginx:latest",
					Runtime:     runtime.Docker,
				},
				"container2": {
					ContainerId: "container2",
					Name:        "redis-container",
					Image:       "redis:7",
					Runtime:     runtime.Containerd,
				},
				"container3": {
					ContainerId: "container3",
					Name:        "postgres-container",
					Image:       "postgres:14",
					Runtime:     runtime.Docker,
				},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: time.Time{}},
				3: {ContainerId: "container3", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(nil)
		require.NoError(t, err)
		assert.Len(t, containers, 3)

		// Verify all containers are returned
		ids := make(map[string]bool)
		for _, c := range containers {
			ids[c.ID] = true
		}
		assert.True(t, ids["container1"])
		assert.True(t, ids["container2"])
		assert.True(t, ids["container3"])
	})

	t.Run("FilterByName", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx-container", Image: "nginx:latest", Runtime: runtime.Docker},
				"container2": {ContainerId: "container2", Name: "redis-container", Image: "redis:7", Runtime: runtime.Containerd},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(datastores.WithName("nginx-container"))
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "container1", containers[0].ID)
		assert.Equal(t, "nginx-container", containers[0].Name)
	})

	t.Run("FilterByImage", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx-1", Image: "nginx:latest", Runtime: runtime.Docker},
				"container2": {ContainerId: "container2", Name: "nginx-2", Image: "nginx:latest", Runtime: runtime.Docker},
				"container3": {ContainerId: "container3", Name: "redis-1", Image: "redis:7", Runtime: runtime.Containerd},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: time.Time{}},
				3: {ContainerId: "container3", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(datastores.WithImage("nginx:latest"))
		require.NoError(t, err)
		require.Len(t, containers, 2)

		// Verify both nginx containers are returned
		for _, c := range containers {
			assert.Equal(t, "nginx:latest", c.Image)
		}
	})

	t.Run("FilterByRuntime", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx", Image: "nginx:latest", Runtime: runtime.Docker},
				"container2": {ContainerId: "container2", Name: "redis", Image: "redis:7", Runtime: runtime.Containerd},
				"container3": {ContainerId: "container3", Name: "postgres", Image: "postgres:14", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: time.Time{}},
				3: {ContainerId: "container3", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(datastores.WithRuntime("docker"))
		require.NoError(t, err)
		require.Len(t, containers, 2)

		// Verify all returned containers are docker
		for _, c := range containers {
			assert.Equal(t, "docker", c.Runtime)
		}
	})

	t.Run("FilterMultipleCriteria", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx-1", Image: "nginx:latest", Runtime: runtime.Docker},
				"container2": {ContainerId: "container2", Name: "nginx-2", Image: "nginx:latest", Runtime: runtime.Containerd},
				"container3": {ContainerId: "container3", Name: "redis", Image: "redis:7", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: time.Time{}},
				3: {ContainerId: "container3", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(
			datastores.WithImage("nginx:latest"),
			datastores.WithRuntime("docker"),
		)
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "container1", containers[0].ID)
		assert.Equal(t, "nginx:latest", containers[0].Image)
		assert.Equal(t, "docker", containers[0].Runtime)
	})

	t.Run("FilterNoMatches", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx", Image: "nginx:latest", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		containers, err := mgr.ListContainers(datastores.WithName("nonexistent"))
		require.NoError(t, err)
		assert.Empty(t, containers)
	})

	t.Run("ExcludesExpiredContainers", func(t *testing.T) {
		now := time.Now()
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "live", Image: "nginx:latest", Runtime: runtime.Docker},
				"container2": {ContainerId: "container2", Name: "expired", Image: "redis:7", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},           // Live (zero time)
				2: {ContainerId: "container2", ContainerRoot: true, expiresAt: now.Add(-time.Minute)}, // Expired
			},
		}

		containers, err := mgr.ListContainers(nil)
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "container1", containers[0].ID)
	})

	t.Run("OnlyContainerRoots", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "root", Image: "nginx:latest", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},  // Root - should be included
				2: {ContainerId: "container1", ContainerRoot: false, expiresAt: time.Time{}}, // Non-root - should be excluded
			},
		}

		containers, err := mgr.ListContainers(nil)
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "container1", containers[0].ID)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx", Image: "nginx:latest", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
			},
			lock: sync.RWMutex{},
		}

		// Run multiple concurrent ListContainers calls
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				containers, err := mgr.ListContainers(nil)
				assert.NoError(t, err)
				assert.Len(t, containers, 1)
			}()
		}
		wg.Wait()
	})

	t.Run("EmptyFilter", func(t *testing.T) {
		mgr := &Manager{
			containerMap: map[string]Container{
				"container1": {ContainerId: "container1", Name: "nginx", Image: "nginx:latest", Runtime: runtime.Docker},
			},
			cgroupsMap: map[uint32]CgroupDir{
				1: {ContainerId: "container1", ContainerRoot: true, expiresAt: time.Time{}},
			},
		}

		// No options should return all containers
		containers, err := mgr.ListContainers()
		require.NoError(t, err)
		assert.Len(t, containers, 1)
	})
}
