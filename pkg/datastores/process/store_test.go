package process

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestProcessTree_DataStoreInterface(t *testing.T) {
	// Create a process tree for testing
	pt, err := NewProcessTree(context.Background(), ProcTreeConfig{
		Source:           SourceNone,
		ProcessCacheSize: 100,
		ThreadCacheSize:  100,
	})
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := pt.Name()
		assert.Equal(t, "process", name)
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := pt.GetHealth()
		require.NotNil(t, health)
		assert.Equal(t, datastores.HealthHealthy, health.Status)
		assert.Empty(t, health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := pt.GetMetrics()
		require.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.ItemCount, int64(0))
	})

	t.Run("GetProcess_NotFound", func(t *testing.T) {
		info, found := pt.GetProcess(999999)
		assert.False(t, found)
		assert.Nil(t, info)
	})

	t.Run("GetChildProcesses_NotFound", func(t *testing.T) {
		children, err := pt.GetChildProcesses(999999)
		assert.NoError(t, err)
		assert.Empty(t, children)
	})

	t.Run("LastAccessTracking", func(t *testing.T) {
		// Get initial metrics
		metrics1 := pt.GetMetrics()
		initialLastAccess := metrics1.LastAccess

		// Sleep briefly to ensure timestamp difference
		time.Sleep(10 * time.Millisecond)

		// Access the datastore
		_, _ = pt.GetProcess(123)

		// Check that LastAccess was updated
		metrics2 := pt.GetMetrics()
		assert.True(t, metrics2.LastAccess.After(initialLastAccess),
			"LastAccess should be updated after GetProcess call")
	})
}
