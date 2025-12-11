package container

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
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
