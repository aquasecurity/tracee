package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// mockRegistry implements dsapi.Registry for testing
type mockRegistry struct {
	stores map[string]dsapi.DataStore
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{
		stores: make(map[string]dsapi.DataStore),
	}
}

func (m *mockRegistry) Processes() dsapi.ProcessStore {
	return nil
}

func (m *mockRegistry) Containers() dsapi.ContainerStore {
	return nil
}

func (m *mockRegistry) KernelSymbols() dsapi.KernelSymbolStore {
	return nil
}

func (m *mockRegistry) DNS() dsapi.DNSStore {
	return nil
}

func (m *mockRegistry) System() dsapi.SystemStore {
	return nil
}

func (m *mockRegistry) Syscalls() dsapi.SyscallStore {
	return nil
}

func (m *mockRegistry) GetCustom(name string) (dsapi.DataStore, error) {
	store, ok := m.stores[name]
	if !ok {
		return nil, dsapi.ErrNotFound
	}
	return store, nil
}

func (m *mockRegistry) RegisterWritableStore(name string, store dsapi.WritableStore) error {
	if m.stores == nil {
		m.stores = make(map[string]dsapi.DataStore)
	}
	m.stores[name] = store
	return nil
}

func (m *mockRegistry) List() []string {
	names := make([]string, 0, len(m.stores))
	for name := range m.stores {
		names = append(names, name)
	}
	return names
}

func (m *mockRegistry) IsAvailable(name string) bool {
	_, ok := m.stores[name]
	return ok
}

func (m *mockRegistry) GetMetadata(name string) (*dsapi.DataStoreMetadata, error) {
	return nil, dsapi.ErrNotFound
}

func (m *mockRegistry) GetMetrics(name string) (*dsapi.DataStoreMetrics, error) {
	return nil, dsapi.ErrNotFound
}

// mockWritableStore implements WritableStore for testing
type mockWritableStore struct {
	name            string
	writeFunc       func(source string, entry *dsapi.DataEntry) error
	writeBatchFunc  func(source string, entries []*dsapi.DataEntry) error
	deleteFunc      func(source string, key *anypb.Any) error
	clearFunc       func(source string) error
	listSourcesFunc func() ([]string, error)
}

func (m *mockWritableStore) Name() string {
	return m.name
}

func (m *mockWritableStore) GetHealth() *dsapi.HealthInfo {
	return &dsapi.HealthInfo{
		Status: dsapi.HealthHealthy,
	}
}

func (m *mockWritableStore) GetMetrics() *dsapi.DataStoreMetrics {
	return &dsapi.DataStoreMetrics{}
}

func (m *mockWritableStore) Write(source string, entry *dsapi.DataEntry) error {
	if m.writeFunc != nil {
		return m.writeFunc(source, entry)
	}
	return nil
}

func (m *mockWritableStore) WriteBatch(source string, entries []*dsapi.DataEntry) error {
	if m.writeBatchFunc != nil {
		return m.writeBatchFunc(source, entries)
	}
	return nil
}

func (m *mockWritableStore) Delete(source string, key *anypb.Any) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(source, key)
	}
	return nil
}

func (m *mockWritableStore) Clear(source string) error {
	if m.clearFunc != nil {
		return m.clearFunc(source)
	}
	return nil
}

func (m *mockWritableStore) ListSources() ([]string, error) {
	if m.listSourcesFunc != nil {
		return m.listSourcesFunc()
	}
	return []string{}, nil
}

// mockNonWritableStore implements DataStore but not WritableStore
type mockNonWritableStore struct {
	name string
}

func (m *mockNonWritableStore) Name() string {
	return m.name
}

func (m *mockNonWritableStore) GetHealth() *dsapi.HealthInfo {
	return &dsapi.HealthInfo{
		Status: dsapi.HealthHealthy,
	}
}

func (m *mockNonWritableStore) GetMetrics() *dsapi.DataStoreMetrics {
	return &dsapi.DataStoreMetrics{}
}

func TestDataStoreService_WriteData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("StoreNotFound", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "nonexistent",
			Source:    "test_source",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Contains(t, st.Message(), "not found")
	})

	t.Run("StoreNotWritable", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockNonWritableStore{name: "readonly_store"}
		registry.stores["readonly_store"] = store

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "readonly_store",
			Source:    "test_source",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Contains(t, st.Message(), "not writable")
	})

	t.Run("MissingStoreName", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			Source: "test_source",
			Entry:  &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("MissingSource", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "test_store",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("MissingEntry", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("WriteError", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{
			name: "test_store",
			writeFunc: func(source string, entry *dsapi.DataEntry) error {
				return dsapi.ErrInvalidArgument
			},
		}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("InternalError", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{
			name: "test_store",
			writeFunc: func(source string, entry *dsapi.DataEntry) error {
				return errors.New("internal error")
			},
		}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Entry:     &dsapi.DataEntry{},
		}

		resp, err := service.WriteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestDataStoreService_WriteBatchData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteBatchDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Entries: []*dsapi.DataEntry{
				{},
				{},
			},
		}

		resp, err := service.WriteBatchData(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, int32(2), resp.WrittenCount)
	})

	t.Run("EmptyEntries", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteBatchDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Entries:   []*dsapi.DataEntry{},
		}

		resp, err := service.WriteBatchData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("StoreNotFound", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteBatchDataRequest{
			StoreName: "nonexistent",
			Source:    "test_source",
			Entries:   []*dsapi.DataEntry{{}},
		}

		resp, err := service.WriteBatchData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("StoreNotWritable", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockNonWritableStore{name: "readonly_store"}
		registry.stores["readonly_store"] = store

		service := &DataStoreService{registry: registry}
		req := &dsapi.WriteBatchDataRequest{
			StoreName: "readonly_store",
			Source:    "test_source",
			Entries:   []*dsapi.DataEntry{{}},
		}

		resp, err := service.WriteBatchData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

func TestDataStoreService_DeleteData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		key, _ := anypb.New(&dsapi.DataEntry{})
		req := &dsapi.DeleteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
			Key:       key,
		}

		resp, err := service.DeleteData(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("MissingKey", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.DeleteDataRequest{
			StoreName: "test_store",
			Source:    "test_source",
		}

		resp, err := service.DeleteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("StoreNotFound", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		key, _ := anypb.New(&dsapi.DataEntry{})
		req := &dsapi.DeleteDataRequest{
			StoreName: "nonexistent",
			Source:    "test_source",
			Key:       key,
		}

		resp, err := service.DeleteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("StoreNotWritable", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockNonWritableStore{name: "readonly_store"}
		registry.stores["readonly_store"] = store

		service := &DataStoreService{registry: registry}
		key, _ := anypb.New(&dsapi.DataEntry{})
		req := &dsapi.DeleteDataRequest{
			StoreName: "readonly_store",
			Source:    "test_source",
			Key:       key,
		}

		resp, err := service.DeleteData(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

func TestDataStoreService_ClearSource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{name: "test_store"}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.ClearSourceRequest{
			StoreName: "test_store",
			Source:    "test_source",
		}

		resp, err := service.ClearSource(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, int32(0), resp.DeletedCount) // Placeholder value
	})

	t.Run("StoreNotFound", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		req := &dsapi.ClearSourceRequest{
			StoreName: "nonexistent",
			Source:    "test_source",
		}

		resp, err := service.ClearSource(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("StoreNotWritable", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockNonWritableStore{name: "readonly_store"}
		registry.stores["readonly_store"] = store

		service := &DataStoreService{registry: registry}
		req := &dsapi.ClearSourceRequest{
			StoreName: "readonly_store",
			Source:    "test_source",
		}

		resp, err := service.ClearSource(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

func TestDataStoreService_ListSources(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{
			name: "test_store",
			listSourcesFunc: func() ([]string, error) {
				return []string{"source1", "source2", "source3"}, nil
			},
		}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.ListSourcesRequest{
			StoreName: "test_store",
		}

		resp, err := service.ListSources(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, []string{"source1", "source2", "source3"}, resp.Sources)
	})

	t.Run("EmptySources", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{
			name: "test_store",
			listSourcesFunc: func() ([]string, error) {
				return []string{}, nil
			},
		}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.ListSourcesRequest{
			StoreName: "test_store",
		}

		resp, err := service.ListSources(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Empty(t, resp.Sources)
	})

	t.Run("StoreNotFound", func(t *testing.T) {
		registry := newMockRegistry()
		service := &DataStoreService{registry: registry}
		req := &dsapi.ListSourcesRequest{
			StoreName: "nonexistent",
		}

		resp, err := service.ListSources(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("StoreNotWritable", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockNonWritableStore{name: "readonly_store"}
		registry.stores["readonly_store"] = store

		service := &DataStoreService{registry: registry}
		req := &dsapi.ListSourcesRequest{
			StoreName: "readonly_store",
		}

		resp, err := service.ListSources(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ListSourcesError", func(t *testing.T) {
		registry := newMockRegistry()
		store := &mockWritableStore{
			name: "test_store",
			listSourcesFunc: func() ([]string, error) {
				return nil, errors.New("list error")
			},
		}
		registry.RegisterWritableStore("test_store", store)

		service := &DataStoreService{registry: registry}
		req := &dsapi.ListSourcesRequest{
			StoreName: "test_store",
		}

		resp, err := service.ListSources(ctx, req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}
