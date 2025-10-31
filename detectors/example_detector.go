package detectors

import (
	"context"
	"fmt"

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
					Name: "parent_process",
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
	var pid, entityID uint32
	if event.Workload != nil && event.Workload.Process != nil {
		if event.Workload.Process.Executable != nil {
			binaryPath = event.Workload.Process.Executable.Path
		}
		if event.Workload.Process.Pid != nil {
			pid = event.Workload.Process.Pid.Value
		}
		if event.Workload.Process.UniqueId != nil {
			entityID = event.Workload.Process.UniqueId.Value
		}
	}

	// Enrich with parent process information using ProcessStore
	parentPath := ""
	if d.dataStores != nil && entityID != 0 {
		processStore := d.dataStores.Processes()
		// Check if ProcessStore is available (it may be disabled in config)
		if processStore != nil {
			// Get current process to find parent
			procInfo, found := processStore.GetProcess(uint64(entityID))
			if found && procInfo.PPID != 0 {
				// Try to get parent process information
				// Note: We need to construct parent entityID from PPID
				// For now, we'll just show the PPID - a real detector would
				// use GetChildProcesses() or walk the process tree
				parentPath = fmt.Sprintf("ppid:%d", procInfo.PPID)

				d.logger.Debugw("Enriched with process info",
					"pid", pid,
					"entity_id", entityID,
					"ppid", procInfo.PPID,
					"process_name", procInfo.Name)
			}
		}
	}

	// Enrich with container information using ContainerStore
	containerID := ""
	containerName := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerID = event.Workload.Container.Id

		// Get additional container details from ContainerStore
		if d.dataStores != nil && containerID != "" {
			containerStore := d.dataStores.Containers()
			if containerStore != nil {
				containerInfo, found := containerStore.GetContainer(containerID)
				if found {
					containerName = containerInfo.Name
					d.logger.Debugw("Enriched with container info",
						"container_id", containerID,
						"container_name", containerName,
						"image_name", containerInfo.Image)
				}
			}
		}
	}

	d.logger.Debugw("ExampleDetector triggered",
		"event_name", event.Name,
		"binary_path", binaryPath,
		"parent_path", parentPath,
		"container_id", containerID,
		"container_name", containerName)

	// Create output event with enriched field data
	outputEvent := v1beta1.CreateEventFromBase(event)
	outputEvent.Data = []*v1beta1.EventValue{
		{
			Name:  "binary_path",
			Value: &v1beta1.EventValue_Str{Str: binaryPath},
		},
		{
			Name:  "parent_process",
			Value: &v1beta1.EventValue_Str{Str: parentPath},
		},
		{
			Name:  "container_id",
			Value: &v1beta1.EventValue_Str{Str: containerID},
		},
		{
			Name:  "container_name",
			Value: &v1beta1.EventValue_Str{Str: containerName},
		},
		{
			Name:  "detection_reason",
			Value: &v1beta1.EventValue_Str{Str: "Example detection - all execve events with DataStore enrichment"},
		},
		{
			Name:  "confidence",
			Value: &v1beta1.EventValue_Int32{Int32: 100},
		},
	}

	return []*v1beta1.Event{outputEvent}, nil
}

func (d *ExampleDetector) Close() error {
	d.logger.Debugw("ExampleDetector closed")
	return nil
}
