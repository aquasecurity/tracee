//go:build e2e

package ebpf

import (
	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/detectors/e2e"
)

func init() {
	// Override the populate function to set e2e registration functions on the Tracee instance
	populateE2eRegistrations = func(t *Tracee) {
		// Set writable data store registration function
		t.registerE2eDatastoresFn = func(reg dsapi.Registry) error {
			return e2e.RegisterE2eDatastores(reg)
		}

		// Expose the e2e writable store as a datastore runtime so the single
		// production DataStoreService serves it (no separate e2e gRPC service).
		t.registerE2eRuntimeFn = func(tr *Tracee) error {
			reg := tr.DataStores()
			ds, err := reg.GetCustom(e2e.E2eWritableStoreName)
			if err != nil {
				return err
			}
			ws, ok := ds.(dsapi.WritableStore)
			if !ok {
				return dsapi.ErrRuntimeUnsupported
			}
			return tr.RegisterDatastoreRuntime(e2e.NewE2eRuntime(e2e.E2eWritableStoreName, ws))
		}
	}
}
