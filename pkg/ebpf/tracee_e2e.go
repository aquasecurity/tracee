//go:build e2e

package ebpf

import (
	"google.golang.org/grpc"

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

		// Set e2e gRPC service registration function
		t.registerE2eGrpcServicesFn = func(grpcServer *grpc.Server, tracee *Tracee) {
			e2e.RegisterE2eGrpcServices(grpcServer, tracee.DataStores())
		}
	}
}
