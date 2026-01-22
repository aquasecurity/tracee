//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// writableStoreReader is implemented by the e2e writable store for detector read access.
type writableStoreReader interface {
	GetValue(key string) (string, bool)
}

func init() { registerE2e(&E2eWritableStore{}) }

// E2eWritableStore is an e2e detector that reads from the writable data store implementation (e2eWritableStore).
// The e2e test writes "bruh" -> "moment" via the writable gRPC and expects this detector to fire on sched_process_exit (comm=ds_writer).
type E2eWritableStore struct {
	logger detection.Logger
	store  writableStoreReader
}

func (d *E2eWritableStore) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "WRITABLE_DATA_STORE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exit",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       E2eWritableStoreName,
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "WRITABLE_DATA_STORE",
			Description: "Instrumentation events E2E Tests: Writable Data Store (DataStoreService + Registry)",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eWritableStore) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	store, err := params.DataStores.GetCustom(E2eWritableStoreName)
	if err != nil {
		// Register the writable data store so this detector (and any gRPC DataStoreService) can use it
		s := NewE2eWritableStore()
		if err := params.DataStores.RegisterWritableStore(E2eWritableStoreName, s); err != nil {
			return err
		}
		store = s
	}
	r, ok := store.(writableStoreReader)
	if !ok {
		return datastores.ErrInvalidArgument
	}
	d.store = r
	d.logger.Debugw("E2eWritableStore detector initialized")
	return nil
}

func (d *E2eWritableStore) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// E2E test: ds_writer process writes key "bruh" value "moment"; we fire when that process exits.
	comm := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		comm = event.Workload.Process.Thread.Name
	}
	if comm != "ds_writer" {
		return nil, nil
	}
	val, ok := d.store.GetValue("bruh")
	if !ok || val != "moment" {
		return nil, nil
	}
	return detection.Detected(), nil
}

func (d *E2eWritableStore) Close() error {
	d.logger.Debugw("E2eWritableStore detector closed")
	return nil
}
