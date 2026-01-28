package symbol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestKernelSymbolTable_DataStoreInterface(t *testing.T) {
	// Create an empty symbol table once for all subtests
	emptyReader := strings.NewReader("")
	kst, err := NewKernelSymbolTableFromReader(emptyReader, false, false)
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := kst.Name()
		assert.Equal(t, "symbol", name)
	})

	t.Run("GetHealth_Empty", func(t *testing.T) {
		health := kst.GetHealth()
		require.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Contains(t, health.Message, "symbol table is empty")
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := kst.GetMetrics()
		require.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.ItemCount, int64(0))
		assert.Equal(t, int64(0), metrics.ItemCount) // Should be 0 for empty table
	})

	t.Run("ResolveSymbolByAddress_NotFound", func(t *testing.T) {
		symbols, err := kst.ResolveSymbolByAddress(0xdeadbeef)
		assert.Error(t, err)
		assert.Nil(t, symbols)
	})

	t.Run("GetSymbolAddress_NotFound", func(t *testing.T) {
		addr, err := kst.GetSymbolAddress("nonexistent_symbol")
		assert.Error(t, err)
		assert.Equal(t, uint64(0), addr)
	})
}
