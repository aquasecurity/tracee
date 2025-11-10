package datastores

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

var _ RegistryManager = (*Registry)(nil) // Compile-time interface check

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

	// Lifecycle tracking
	initialized map[string]bool
}

// NewRegistry creates a new datastore registry
func NewRegistry() *Registry {
	return &Registry{
		stores:      make(map[string]datastores.DataStore),
		initialized: make(map[string]bool),
		// Initialize with null objects to ensure accessor methods never return nil
		processStore:      &nullProcessStore{},
		containerStore:    &nullContainerStore{},
		kernelSymbolStore: &nullKernelSymbolStore{},
		dnsStore:          &nullDNSStore{},
		systemStore:       &nullSystemStore{},
		syscallStore:      &nullSyscallStore{},
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
	case datastores.Process:
		if ps, ok := store.(datastores.ProcessStore); ok {
			r.processStore = ps
		}
	case datastores.Container:
		if cs, ok := store.(datastores.ContainerStore); ok {
			r.containerStore = cs
		}
	case datastores.Symbol:
		if ks, ok := store.(datastores.KernelSymbolStore); ok {
			r.kernelSymbolStore = ks
		}
	case datastores.DNS:
		if ds, ok := store.(datastores.DNSStore); ok {
			r.dnsStore = ds
		}
	case datastores.System:
		if ss, ok := store.(datastores.SystemStore); ok {
			r.systemStore = ss
		}
	case datastores.Syscall:
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

// RegisterWritableStore registers a new writable datastore
// The caller becomes the owner of the store and can write to it
// Other consumers can access the store via GetCustom() for read-only operations
// Returns error if a store with the same name already exists
func (r *Registry) RegisterWritableStore(name string, store datastores.WritableStore) error {
	if isNilInterface(store) {
		return fmt.Errorf("writable datastore '%s' cannot be nil", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicates
	if _, exists := r.stores[name]; exists {
		return fmt.Errorf("datastore '%s' already registered", name)
	}

	// Register the writable store (it's also a DataStore)
	r.stores[name] = store

	return nil
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

// InitializeAll initializes all registered datastores
// Detects and calls Initialize(context.Context) on stores that implement it
// Returns an error if any datastore fails to initialize
// Already-initialized stores are skipped
func (r *Registry) InitializeAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Optional lifecycle interface - stores can implement this for initialization
	type initializer interface {
		Initialize(context.Context) error
	}

	for name, store := range r.stores {
		// Skip already initialized stores
		if r.initialized[name] {
			continue
		}

		// Check if store implements optional Initialize method
		if init, ok := store.(initializer); ok {
			if err := init.Initialize(ctx); err != nil {
				return fmt.Errorf("failed to initialize datastore '%s': %w", name, err)
			}
		}

		r.initialized[name] = true
	}

	return nil
}

// ShutdownAll gracefully shuts down all initialized datastores
// Detects and calls Shutdown(context.Context) on stores that implement it
// Continues shutting down remaining stores even if one fails
// Returns the first error encountered, if any
func (r *Registry) ShutdownAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Optional lifecycle interface - stores can implement this for cleanup
	type shutdowner interface {
		Shutdown(context.Context) error
	}

	var firstErr error

	// Shutdown in reverse registration order for proper cleanup
	names := make([]string, 0, len(r.stores))
	for name := range r.stores {
		if r.initialized[name] {
			names = append(names, name)
		}
	}

	// Reverse the order
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		store := r.stores[name]

		// Check if store implements optional Shutdown method
		if shutdown, ok := store.(shutdowner); ok {
			if err := shutdown.Shutdown(ctx); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to shutdown datastore '%s': %w", name, err)
				}
				// Continue shutdown even if one fails
			}
		}

		r.initialized[name] = false
	}

	return firstErr
}

// Registry returns itself as the Registry interface
// This allows the Registry struct to implement RegistryManager
func (r *Registry) Registry() datastores.Registry {
	return r
}

// GetContainerManager returns the concrete container.Manager for internal Tracee use
// Returns nil if the container store is not registered or is of wrong type
func (r *Registry) GetContainerManager() *container.Manager {
	if r.containerStore == nil {
		return nil
	}
	mgr, ok := r.containerStore.(*container.Manager)
	if !ok {
		return nil
	}
	return mgr
}

// GetProcessTree returns the concrete process.ProcessTree for internal Tracee use
// Returns nil if the process store is not registered or is of wrong type
func (r *Registry) GetProcessTree() *process.ProcessTree {
	if r.processStore == nil {
		return nil
	}
	tree, ok := r.processStore.(*process.ProcessTree)
	if !ok {
		return nil
	}
	return tree
}

// GetDNSCache returns the concrete dns.DNSCache for internal Tracee use
// Returns nil if the DNS store is not registered or is of wrong type
func (r *Registry) GetDNSCache() *dns.DNSCache {
	if r.dnsStore == nil {
		return nil
	}
	cache, ok := r.dnsStore.(*dns.DNSCache)
	if !ok {
		return nil
	}
	return cache
}
