package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&ExampleDetector{})
}

// ExampleDetector is a demonstration detector that shows the detector API patterns.
// It detects all execve events and produces an example_detection event.
// This detector demonstrates:
// - How to use the DataStore API (ProcessStore and ContainerStore)
// - How to enrich detections with contextual information
// - Best practices for detector implementation
type ExampleDetector struct {
	logger     detection.Logger
	dataStores datastores.Registry
}

func (d *ExampleDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "EXAMPLE-001",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "execve",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       "container",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "example_detection",
			Description: "Example detection demonstrating the detector API and DataStore usage",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{
					Name: "binary_path",
					Type: "const char*",
				},
				{
					Name: "container_id",
					Type: "const char*",
				},
				{
					Name: "container_name",
					Type: "const char*",
				},
				{
					Name: "container_image",
					Type: "const char*",
				},
				{
					Name: "detection_reason",
					Type: "const char*",
				},
				{
					Name: "confidence",
					Type: "int",
				},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Example Threat",
			Description: "This is an example threat detection for testing purposes",
			Severity:    v1beta1.Severity_LOW,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Execution",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1059",
					Name: "Command and Scripting Interpreter",
				},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *ExampleDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores
	d.logger.Debugw("ExampleDetector initialized",
		"has_datastores", d.dataStores != nil)
	return nil
}

func (d *ExampleDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]*v1beta1.Event, error) {
	// This is a demonstration detector - it triggers on all execve events
	// Real detectors would have actual detection logic here
	if event.Name != "execve" {
		return nil, nil
	}

	// Get basic process information from the event
	binaryPath := ""
	var pid uint32
	if event.Workload != nil && event.Workload.Process != nil {
		if event.Workload.Process.Executable != nil {
			binaryPath = event.Workload.Process.Executable.Path
		}
		if event.Workload.Process.Pid != nil {
			pid = event.Workload.Process.Pid.Value
		}
	}

	// Enrich with container information using ContainerStore
	containerID := ""
	containerName := ""
	containerImage := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerID = event.Workload.Container.Id

		// Get additional container details from ContainerStore
		if d.dataStores != nil && containerID != "" {
			containerStore := d.dataStores.Containers()
			if containerStore != nil {
				containerInfo, found := containerStore.GetContainer(containerID)
				if found {
					containerName = containerInfo.Name
					containerImage = containerInfo.Image
					d.logger.Debugw("Enriched with container info",
						"container_id", containerID,
						"container_name", containerName,
						"image_name", containerImage)
				}
			}
		}
	}

	d.logger.Debugw("ExampleDetector triggered",
		"event_name", event.Name,
		"binary_path", binaryPath,
		"pid", pid,
		"container_id", containerID,
		"container_name", containerName)

	// Create output event with enriched field data
	outputEvent := v1beta1.CreateEventFromBase(event)

	// Always include binary path if available
	if binaryPath != "" {
		outputEvent.Data = append(outputEvent.Data, v1beta1.NewStringValue("binary_path", binaryPath))
	}

	// Add container information if event is from a container
	if containerID != "" {
		outputEvent.Data = append(outputEvent.Data, v1beta1.NewStringValue("container_id", containerID))
	}

	// Add detection metadata
	outputEvent.Data = append(outputEvent.Data,
		v1beta1.NewStringValue("detection_reason", "Example detection - all execve events with DataStore enrichment"),
		v1beta1.NewInt32Value("confidence", 100),
	)

	return []*v1beta1.Event{outputEvent}, nil
}

func (d *ExampleDetector) Close() error {
	d.logger.Debugw("ExampleDetector closed")
	return nil
}
