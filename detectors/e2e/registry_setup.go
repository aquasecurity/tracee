//go:build e2e

package e2e

import (
	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// RegisterE2eDatastores registers e2e-only datastores with the registry.
// Called by pkg/ebpf/tracee_e2e.go during tracee initialization (before detector registration).
func RegisterE2eDatastores(reg dsapi.Registry) error {
	return reg.RegisterWritableStore(E2eWritableStoreName, NewE2eWritableStore())
}
