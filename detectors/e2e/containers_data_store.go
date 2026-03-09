//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eContainersDataStore{}) }

// E2eContainersDataStore is an e2e test detector for testing the containers data store API.
// Origin: "container" -> Uses ScopeFilters: container=started.
type E2eContainersDataStore struct {
	logger         detection.Logger
	containerStore datastores.ContainerStore
}

func (d *E2eContainersDataStore) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "CONTAINERS_DATA_STORE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "sched_process_exec",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       datastores.Container,
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "CONTAINERS_DATA_STORE",
			Description: "Instrumentation events E2E Tests: Containers Data Store Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eContainersDataStore) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.containerStore = params.DataStores.Containers()
	d.logger.Debugw("E2eContainersDataStore detector initialized")
	return nil
}

func (d *E2eContainersDataStore) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	if pathname != "/bin/ls" {
		return nil, nil
	}

	// Get container ID from the event
	containerID := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerID = event.Workload.Container.Id
	}

	if containerID == "" {
		d.logger.Warnw("received non container event")
		return nil, nil
	}

	// Query the container store
	containerInfo, err := d.containerStore.GetContainer(containerID)
	if err != nil {
		d.logger.Warnw("failed to find container in data store", "container_id", containerID, "error", err)
		return nil, nil
	}

	if containerInfo.ID != containerID {
		d.logger.Warnw("container id mismatch", "expected", containerID, "got", containerInfo.ID)
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eContainersDataStore) Close() error {
	d.logger.Debugw("E2eContainersDataStore detector closed")
	return nil
}
