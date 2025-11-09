package dns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestDNSCache_DataStoreInterface(t *testing.T) {
	cache, err := New(Config{
		CacheSize: 100,
		Enable:    true,
	})
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := cache.Name()
		assert.Equal(t, "dns", name)
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := cache.GetHealth()
		require.NotNil(t, health)
		assert.Equal(t, datastores.HealthHealthy, health.Status)
		assert.Empty(t, health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := cache.GetMetrics()
		require.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.ItemCount, int64(0))
	})

	t.Run("GetDNSResponse_NotFound", func(t *testing.T) {
		resp, err := cache.GetDNSResponse("nonexistent.example.com")
		assert.ErrorIs(t, err, datastores.ErrNotFound)
		assert.Nil(t, resp)
	})

	t.Run("LastAccessTracking", func(t *testing.T) {
		// Get initial metrics
		metrics1 := cache.GetMetrics()
		initialLastAccess := metrics1.LastAccess

		// Sleep briefly to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Access the datastore
		_, _ = cache.GetDNSResponse("test.example.com")

		// Check that LastAccess was updated
		metrics2 := cache.GetMetrics()
		assert.True(t, metrics2.LastAccess.After(initialLastAccess),
			"LastAccess should be updated after GetDNSResponse call")
	})
}
