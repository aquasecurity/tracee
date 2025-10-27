package datastores

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// mockDataStore is a simple mock for testing
type mockDataStore struct {
	name string
}

func (m *mockDataStore) Name() string                             { return m.name }
func (m *mockDataStore) GetHealth() *datastores.HealthInfo        { return nil }
func (m *mockDataStore) GetMetrics() *datastores.DataStoreMetrics { return nil }

// mockProcessStore implements ProcessStore for testing
type mockProcessStore struct {
	mockDataStore
}

func (m *mockProcessStore) GetProcess(entityId uint64) (*datastores.ProcessInfo, bool) {
	return nil, false
}

func (m *mockProcessStore) GetChildProcesses(entityId uint64) ([]*datastores.ProcessInfo, error) {
	return nil, nil
}

func (m *mockProcessStore) GetAncestry(entityId uint64, maxDepth int) ([]*datastores.ProcessInfo, error) {
	return nil, nil
}

// mockContainerStore implements ContainerStore for testing
type mockContainerStore struct {
	mockDataStore
}

func (m *mockContainerStore) GetContainer(id string) (*datastores.ContainerInfo, bool) {
	return nil, false
}

func (m *mockContainerStore) GetContainerByName(name string) (*datastores.ContainerInfo, bool) {
	return nil, false
}

func TestRegistry_RegisterStore(t *testing.T) {
	t.Run("RegisterStore_Success", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "test"}

		err := reg.RegisterStore("test", store, false)
		assert.NoError(t, err)
		assert.True(t, reg.IsAvailable("test"))
	})

	t.Run("RegisterStore_Duplicate", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "test"}

		err := reg.RegisterStore("test", store, false)
		require.NoError(t, err)

		err = reg.RegisterStore("test", store, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("RegisterStore_NilRequired", func(t *testing.T) {
		reg := NewRegistry()

		err := reg.RegisterStore("test", nil, true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("RegisterStore_NilOptional", func(t *testing.T) {
		reg := NewRegistry()

		err := reg.RegisterStore("test", nil, false)
		assert.NoError(t, err)
		assert.False(t, reg.IsAvailable("test"))
	})
}

func TestRegistry_Processes(t *testing.T) {
	t.Run("Processes_Found", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockProcessStore{mockDataStore: mockDataStore{name: "process"}}

		err := reg.RegisterStore("process", store, true)
		require.NoError(t, err)

		result := reg.Processes()
		assert.NotNil(t, result)
		assert.Equal(t, "process", result.Name())
	})

	t.Run("Processes_NotFound", func(t *testing.T) {
		reg := NewRegistry()

		result := reg.Processes()
		assert.Nil(t, result)
	})

	t.Run("Processes_WrongType", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "process"}

		err := reg.RegisterStore("process", store, false)
		require.NoError(t, err)

		result := reg.Processes()
		assert.Nil(t, result, "should return nil when store doesn't implement ProcessStore")
	})
}

func TestRegistry_Containers(t *testing.T) {
	t.Run("Containers_Found", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockContainerStore{mockDataStore: mockDataStore{name: "container"}}

		err := reg.RegisterStore("container", store, true)
		require.NoError(t, err)

		result := reg.Containers()
		assert.NotNil(t, result)
		assert.Equal(t, "container", result.Name())
	})

	t.Run("Containers_NotFound", func(t *testing.T) {
		reg := NewRegistry()

		result := reg.Containers()
		assert.Nil(t, result)
	})
}

func TestRegistry_GetCustom(t *testing.T) {
	t.Run("GetCustom_Found", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "custom"}

		err := reg.RegisterStore("custom", store, false)
		require.NoError(t, err)

		result, err := reg.GetCustom("custom")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "custom", result.Name())
	})

	t.Run("GetCustom_NotFound", func(t *testing.T) {
		reg := NewRegistry()

		result, err := reg.GetCustom("nonexistent")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry()

	// Initially empty
	list := reg.List()
	assert.Empty(t, list)

	// Add stores
	reg.RegisterStore("store1", &mockDataStore{name: "store1"}, false)
	reg.RegisterStore("store2", &mockDataStore{name: "store2"}, false)

	list = reg.List()
	assert.Len(t, list, 2)
	assert.Contains(t, list, "store1")
	assert.Contains(t, list, "store2")
}

func TestRegistry_IsAvailable(t *testing.T) {
	reg := NewRegistry()

	assert.False(t, reg.IsAvailable("test"))

	reg.RegisterStore("test", &mockDataStore{name: "test"}, false)

	assert.True(t, reg.IsAvailable("test"))
	assert.False(t, reg.IsAvailable("nonexistent"))
}

func TestRegistry_GetMetadata(t *testing.T) {
	t.Run("GetMetadata_Found", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "test"}

		err := reg.RegisterStore("test", store, false)
		require.NoError(t, err)

		metadata, err := reg.GetMetadata("test")
		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, "test", metadata.Name)
	})

	t.Run("GetMetadata_NotFound", func(t *testing.T) {
		reg := NewRegistry()

		metadata, err := reg.GetMetadata("nonexistent")
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRegistry_GetMetrics(t *testing.T) {
	t.Run("GetMetrics_Found", func(t *testing.T) {
		reg := NewRegistry()
		store := &mockDataStore{name: "test"}

		err := reg.RegisterStore("test", store, false)
		require.NoError(t, err)

		metrics, err := reg.GetMetrics("test")
		assert.NoError(t, err)
		assert.Nil(t, metrics) // mockDataStore returns nil
	})

	t.Run("GetMetrics_NotFound", func(t *testing.T) {
		reg := NewRegistry()

		metrics, err := reg.GetMetrics("nonexistent")
		assert.Error(t, err)
		assert.Nil(t, metrics)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRegistry_Concurrency(t *testing.T) {
	// Test concurrent access to registry
	reg := NewRegistry()

	// Register initial stores
	for i := 0; i < 5; i++ {
		store := &mockDataStore{name: "store"}
		reg.RegisterStore(string(rune('a'+i)), store, false)
	}

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				reg.IsAvailable("a")
				reg.List()
				reg.GetCustom("a")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
