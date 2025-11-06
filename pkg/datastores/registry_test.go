package datastores

import (
	"context"
	"errors"
	"testing"
	"time"

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

func (m *mockProcessStore) GetProcess(entityId uint32) (*datastores.ProcessInfo, bool) {
	return nil, false
}

func (m *mockProcessStore) GetChildProcesses(entityId uint32) ([]*datastores.ProcessInfo, error) {
	return nil, nil
}

func (m *mockProcessStore) GetAncestry(entityId uint32, maxDepth int) ([]*datastores.ProcessInfo, error) {
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
		store := &mockProcessStore{mockDataStore: mockDataStore{name: datastores.Process}}

		err := reg.RegisterStore(datastores.Process, store, true)
		require.NoError(t, err)

		result := reg.Processes()
		assert.NotNil(t, result)
		assert.Equal(t, datastores.Process, result.Name())
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
		store := &mockContainerStore{mockDataStore: mockDataStore{name: datastores.Container}}

		err := reg.RegisterStore(datastores.Container, store, true)
		require.NoError(t, err)

		result := reg.Containers()
		assert.NotNil(t, result)
		assert.Equal(t, datastores.Container, result.Name())
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

// mockLifecycleStore implements optional lifecycle methods
type mockLifecycleStore struct {
	name             string
	initializeCalled bool
	shutdownCalled   bool
	initializeError  error
	shutdownError    error
}

func (m *mockLifecycleStore) Name() string { return m.name }

func (m *mockLifecycleStore) Initialize(ctx context.Context) error {
	m.initializeCalled = true
	return m.initializeError
}

func (m *mockLifecycleStore) Shutdown(ctx context.Context) error {
	m.shutdownCalled = true
	return m.shutdownError
}

func (m *mockLifecycleStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockLifecycleStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

// mockSimpleStore does NOT implement lifecycle methods
type mockSimpleStore struct {
	name string
}

func (m *mockSimpleStore) Name() string { return m.name }
func (m *mockSimpleStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}
func (m *mockSimpleStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func TestRegistry_InitializeAll(t *testing.T) {
	t.Run("successful initialization", func(t *testing.T) {
		registry := NewRegistry()
		store1 := &mockLifecycleStore{name: "store1"}
		store2 := &mockLifecycleStore{name: "store2"}

		require.NoError(t, registry.RegisterStore("store1", store1, false))
		require.NoError(t, registry.RegisterStore("store2", store2, false))

		err := registry.InitializeAll(context.Background())
		require.NoError(t, err)

		assert.True(t, store1.initializeCalled)
		assert.True(t, store2.initializeCalled)
		assert.True(t, registry.initialized["store1"])
		assert.True(t, registry.initialized["store2"])
	})

	t.Run("initialization failure", func(t *testing.T) {
		registry := NewRegistry()
		store1 := &mockLifecycleStore{name: "store1"}
		store2 := &mockLifecycleStore{
			name:            "store2",
			initializeError: errors.New("init failed"),
		}

		require.NoError(t, registry.RegisterStore("store1", store1, false))
		require.NoError(t, registry.RegisterStore("store2", store2, false))

		err := registry.InitializeAll(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize datastore")
	})

	t.Run("skip already initialized", func(t *testing.T) {
		registry := NewRegistry()
		store1 := &mockLifecycleStore{name: "store1"}

		require.NoError(t, registry.RegisterStore("store1", store1, false))

		err := registry.InitializeAll(context.Background())
		require.NoError(t, err)
		assert.True(t, store1.initializeCalled)

		store1.initializeCalled = false
		err = registry.InitializeAll(context.Background())
		require.NoError(t, err)
		assert.False(t, store1.initializeCalled, "Should not reinitialize")
	})

	t.Run("context cancellation", func(t *testing.T) {
		registry := NewRegistry()

		// Store that checks context
		slowStore := &mockLifecycleStore{name: "slow"}
		slowStore.initializeError = context.Canceled

		require.NoError(t, registry.RegisterStore("slow", slowStore, false))

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := registry.InitializeAll(ctx)
		// Store's Initialize should respect context
		assert.Error(t, err)
	})

	t.Run("store without Initialize works", func(t *testing.T) {
		registry := NewRegistry()
		simple := &mockSimpleStore{name: "simple"}

		require.NoError(t, registry.RegisterStore("simple", simple, false))

		err := registry.InitializeAll(context.Background())
		require.NoError(t, err)
		assert.True(t, registry.initialized["simple"])
	})
}

func TestRegistry_ShutdownAll(t *testing.T) {
	t.Run("successful shutdown", func(t *testing.T) {
		registry := NewRegistry()
		store1 := &mockLifecycleStore{name: "store1"}
		store2 := &mockLifecycleStore{name: "store2"}

		require.NoError(t, registry.RegisterStore("store1", store1, false))
		require.NoError(t, registry.RegisterStore("store2", store2, false))
		require.NoError(t, registry.InitializeAll(context.Background()))

		err := registry.ShutdownAll(context.Background())
		require.NoError(t, err)

		assert.True(t, store1.shutdownCalled)
		assert.True(t, store2.shutdownCalled)
		assert.False(t, registry.initialized["store1"])
		assert.False(t, registry.initialized["store2"])
	})

	t.Run("shutdown continues on error", func(t *testing.T) {
		registry := NewRegistry()
		store1 := &mockLifecycleStore{name: "store1"}
		store2 := &mockLifecycleStore{
			name:          "store2",
			shutdownError: errors.New("shutdown failed"),
		}

		require.NoError(t, registry.RegisterStore("store1", store1, false))
		require.NoError(t, registry.RegisterStore("store2", store2, false))
		require.NoError(t, registry.InitializeAll(context.Background()))

		err := registry.ShutdownAll(context.Background())
		require.Error(t, err)

		// Both should be called despite error
		assert.True(t, store1.shutdownCalled)
		assert.True(t, store2.shutdownCalled)
	})

	t.Run("context timeout", func(t *testing.T) {
		registry := NewRegistry()
		store := &mockLifecycleStore{name: "store"}

		require.NoError(t, registry.RegisterStore("store", store, false))
		require.NoError(t, registry.InitializeAll(context.Background()))

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// ShutdownAll should respect context (though store might not)
		_ = registry.ShutdownAll(ctx)
		assert.True(t, store.shutdownCalled)
	})
}

func TestRegistry_RegistryMethod(t *testing.T) {
	registry := NewRegistry()

	// Verify Registry() returns itself
	publicRegistry := registry.Registry()
	assert.NotNil(t, publicRegistry)

	// Verify it's the same instance
	assert.Equal(t, registry, publicRegistry)
}
