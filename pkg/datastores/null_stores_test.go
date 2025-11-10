package datastores

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestNullProcessStore(t *testing.T) {
	store := &nullProcessStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_process", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "process store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("GetProcess", func(t *testing.T) {
		proc, err := store.GetProcess(1)
		assert.Nil(t, proc)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("GetChildProcesses", func(t *testing.T) {
		children, err := store.GetChildProcesses(1)
		assert.Nil(t, children)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("GetAncestry", func(t *testing.T) {
		ancestry, err := store.GetAncestry(1, 10)
		assert.Nil(t, ancestry)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

func TestNullContainerStore(t *testing.T) {
	store := &nullContainerStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_container", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "container store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("GetContainer", func(t *testing.T) {
		container, err := store.GetContainer("test-id")
		assert.Nil(t, container)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("GetContainerByName", func(t *testing.T) {
		container, err := store.GetContainerByName("test-name")
		assert.Nil(t, container)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

func TestNullKernelSymbolStore(t *testing.T) {
	store := &nullKernelSymbolStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_symbol", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "kernel symbol store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("ResolveSymbolByAddress", func(t *testing.T) {
		symbols, err := store.ResolveSymbolByAddress(0x12345678)
		assert.Nil(t, symbols)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("GetSymbolAddress", func(t *testing.T) {
		addr, err := store.GetSymbolAddress("test_symbol")
		assert.Equal(t, uint64(0), addr)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("ResolveSymbolsBatch", func(t *testing.T) {
		addrs := []uint64{0x1000, 0x2000, 0x3000}
		result, err := store.ResolveSymbolsBatch(addrs)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

func TestNullDNSStore(t *testing.T) {
	store := &nullDNSStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_dns", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "DNS store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("GetDNSResponse", func(t *testing.T) {
		response, err := store.GetDNSResponse("example.com")
		assert.Nil(t, response)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

func TestNullSystemStore(t *testing.T) {
	store := &nullSystemStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_system", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "system store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("GetSystemInfo", func(t *testing.T) {
		info := store.GetSystemInfo()
		assert.NotNil(t, info)
		// Verify it returns an empty SystemInfo struct
		assert.Equal(t, &datastores.SystemInfo{}, info)
	})
}

func TestNullSyscallStore(t *testing.T) {
	store := &nullSyscallStore{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "null_syscall", store.Name())
	})

	t.Run("GetHealth", func(t *testing.T) {
		health := store.GetHealth()
		assert.NotNil(t, health)
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)
		assert.Equal(t, "syscall store not available", health.Message)
		assert.False(t, health.LastCheck.IsZero())
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.False(t, metrics.LastAccess.IsZero())
	})

	t.Run("GetSyscallName", func(t *testing.T) {
		name, err := store.GetSyscallName(1)
		assert.Equal(t, "", name)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("GetSyscallID", func(t *testing.T) {
		id, err := store.GetSyscallID("read")
		assert.Equal(t, int32(0), id)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

// TestNullStores_RegistryIntegration tests that null stores are properly returned by the registry
func TestNullStores_RegistryIntegration(t *testing.T) {
	t.Run("Processes returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.Processes()

		assert.NotNil(t, store)
		assert.Equal(t, "null_process", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		_, err := store.GetProcess(1)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("Containers returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.Containers()

		assert.NotNil(t, store)
		assert.Equal(t, "null_container", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		_, err := store.GetContainer("test")
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("KernelSymbols returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.KernelSymbols()

		assert.NotNil(t, store)
		assert.Equal(t, "null_symbol", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		_, err := store.GetSymbolAddress("test")
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("DNS returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.DNS()

		assert.NotNil(t, store)
		assert.Equal(t, "null_dns", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		_, err := store.GetDNSResponse("example.com")
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})

	t.Run("System returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.System()

		assert.NotNil(t, store)
		assert.Equal(t, "null_system", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		info := store.GetSystemInfo()
		assert.NotNil(t, info)
	})

	t.Run("Syscalls returns null store when not registered", func(t *testing.T) {
		reg := NewRegistry()
		store := reg.Syscalls()

		assert.NotNil(t, store)
		assert.Equal(t, "null_syscall", store.Name())

		health := store.GetHealth()
		assert.Equal(t, datastores.HealthUnhealthy, health.Status)

		_, err := store.GetSyscallName(1)
		assert.ErrorIs(t, err, datastores.ErrStoreUnhealthy)
	})
}

// TestNullStores_SafeMethodChaining verifies that null stores enable safe method chaining
func TestNullStores_SafeMethodChaining(t *testing.T) {
	reg := NewRegistry()

	// All these chains should work without nil checks
	t.Run("Process store chaining", func(t *testing.T) {
		// This would panic with nil, but works with null object
		name := reg.Processes().Name()
		assert.Equal(t, "null_process", name)

		status := reg.Processes().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)

		count := reg.Processes().GetMetrics().ItemCount
		assert.Equal(t, int64(0), count)
	})

	t.Run("Container store chaining", func(t *testing.T) {
		name := reg.Containers().Name()
		assert.Equal(t, "null_container", name)

		status := reg.Containers().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)
	})

	t.Run("KernelSymbol store chaining", func(t *testing.T) {
		name := reg.KernelSymbols().Name()
		assert.Equal(t, "null_symbol", name)

		status := reg.KernelSymbols().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)
	})

	t.Run("DNS store chaining", func(t *testing.T) {
		name := reg.DNS().Name()
		assert.Equal(t, "null_dns", name)

		status := reg.DNS().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)
	})

	t.Run("System store chaining", func(t *testing.T) {
		name := reg.System().Name()
		assert.Equal(t, "null_system", name)

		status := reg.System().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)
	})

	t.Run("Syscall store chaining", func(t *testing.T) {
		name := reg.Syscalls().Name()
		assert.Equal(t, "null_syscall", name)

		status := reg.Syscalls().GetHealth().Status
		assert.Equal(t, datastores.HealthUnhealthy, status)
	})
}
