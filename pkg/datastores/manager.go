package datastores

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// RegistryManager provides lifecycle management for datastores (internal to Tracee)
// This is separate from the public Registry interface which is read-only for detectors
type RegistryManager interface {
	// RegisterStore registers a datastore with lifecycle management
	RegisterStore(name string, store datastores.DataStore, required bool) error

	// InitializeAll initializes all registered datastores
	// Calls Initialize(ctx) on stores that implement it
	InitializeAll(ctx context.Context) error

	// ShutdownAll gracefully shuts down all initialized datastores
	// Calls Shutdown(ctx) on stores that implement it, in reverse order
	ShutdownAll(ctx context.Context) error

	// Registry returns the public read-only registry for detector access
	Registry() datastores.Registry
}
