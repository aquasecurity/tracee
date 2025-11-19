package datastores

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// Registry implements the datastores.Registry interface and provides
// store registration capabilities for internal Tracee use
type Registry struct {
	stores map[string]datastores.DataStore
	mu     sync.RWMutex

	// Typed references to core stores for efficient access
	processStore      datastores.ProcessStore
	containerStore    datastores.ContainerStore
	kernelSymbolStore datastores.KernelSymbolStore
	dnsStore          datastores.DNSStore
	systemStore       datastores.SystemStore
	syscallStore      datastores.SyscallStore
}

// NewRegistry creates a new datastore registry
func NewRegistry() *Registry {
	return &Registry{
		stores: make(map[string]datastores.DataStore),
	}
}

// isNilInterface checks if an interface wraps a nil concrete value
// This handles the Go "interface nil gotcha" where an interface containing
// a typed nil pointer is not equal to nil
func isNilInterface(i interface{}) bool {
	if i == nil {
		return true
	}
	v := reflect.ValueOf(i)
	kind := v.Kind()
	// Only pointer-like types can be nil
	return (kind == reflect.Ptr || kind == reflect.Interface ||
		kind == reflect.Slice || kind == reflect.Map ||
		kind == reflect.Chan || kind == reflect.Func) && v.IsNil()
}

// RegisterStore registers a datastore with the given name
// If required is true, returns an error if the store is nil
func (r *Registry) RegisterStore(name string, store datastores.DataStore, required bool) error {
	if isNilInterface(store) {
		if required {
			return fmt.Errorf("required datastore '%s' is nil", name)
		}
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicates
	if _, exists := r.stores[name]; exists {
		return fmt.Errorf("datastore '%s' already registered", name)
	}

	// Store typed references for core datastores
	switch name {
	case "process":
		if ps, ok := store.(datastores.ProcessStore); ok {
			r.processStore = ps
		}
	case "container":
		if cs, ok := store.(datastores.ContainerStore); ok {
			r.containerStore = cs
		}
	case "symbol":
		if ks, ok := store.(datastores.KernelSymbolStore); ok {
			r.kernelSymbolStore = ks
		}
	case "dns":
		if ds, ok := store.(datastores.DNSStore); ok {
			r.dnsStore = ds
		}
	case "system":
		if ss, ok := store.(datastores.SystemStore); ok {
			r.systemStore = ss
		}
	case "syscall":
		if sc, ok := store.(datastores.SyscallStore); ok {
			r.syscallStore = sc
		}
	}

	r.stores[name] = store

	return nil
}

// Processes returns the process datastore
func (r *Registry) Processes() datastores.ProcessStore {
	return r.processStore
}

// Containers returns the container datastore
func (r *Registry) Containers() datastores.ContainerStore {
	return r.containerStore
}

// KernelSymbols returns the kernel symbol datastore
func (r *Registry) KernelSymbols() datastores.KernelSymbolStore {
	return r.kernelSymbolStore
}

// DNS returns the DNS cache datastore
func (r *Registry) DNS() datastores.DNSStore {
	return r.dnsStore
}

// System returns the system information datastore
func (r *Registry) System() datastores.SystemStore {
	return r.systemStore
}

// Syscalls returns the syscall information datastore
func (r *Registry) Syscalls() datastores.SyscallStore {
	return r.syscallStore
}

// GetCustom returns a custom datastore by name with type safety
func (r *Registry) GetCustom(name string) (datastores.DataStore, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	store, ok := r.stores[name]
	if !ok {
		return nil, fmt.Errorf("datastore '%s' not found", name)
	}

	return store, nil
}

// List returns a list of all registered datastore names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.stores))
	for name := range r.stores {
		names = append(names, name)
	}

	return names
}

// IsAvailable checks if a datastore with the given name is registered
func (r *Registry) IsAvailable(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.stores[name]
	return ok
}

// GetMetadata returns metadata for a specific datastore
func (r *Registry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	store, ok := r.stores[name]
	if !ok {
		return nil, fmt.Errorf("datastore '%s' not found", name)
	}

	return &datastores.DataStoreMetadata{
		Name:        store.Name(),
		Description: "", // Phase 2: Add description field to DataStore interface
		Config:      nil,
	}, nil
}

// GetMetrics returns metrics for a specific datastore
func (r *Registry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	store, ok := r.stores[name]
	if !ok {
		return nil, fmt.Errorf("datastore '%s' not found", name)
	}

	return store.GetMetrics(), nil
}
