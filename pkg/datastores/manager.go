package datastores

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
)

// RegistryManager provides lifecycle management for datastores (internal to Tracee)
// This is separate from the public Registry interface which is read-only for detectors
type RegistryManager interface {
	// Lifecycle management
	RegisterStore(name string, store datastores.DataStore, required bool) error
	InitializeAll(ctx context.Context) error
	ShutdownAll(ctx context.Context) error

	// Public registry for detectors (read-only access)
	Registry() datastores.Registry

	// Internal accessors for Tracee (return concrete types with full API)
	// These methods return nil if the store is not registered or is of wrong type
	GetContainerManager() *container.Manager
	GetProcessTree() *process.ProcessTree
	GetDNSCache() *dns.DNSCache
}
