//go:build detectorexamples

// This example detector is excluded from default builds to prevent noise in production.
// To build Tracee with this example included, use:
//   make tracee-with-examples

package detectors

import (
	"context"
	"errors"

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
// - How to use the DataStore API (ContainerStore and SystemStore)
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
					// Example scope filters (uncomment to use):
					// ScopeFilters: []string{"container=started"}, // Only events from started containers
					// ScopeFilters: []string{"host"},              // Only events from host (not containers)
					// ScopeFilters: []string{"container"},         // Any container (started or not)

					// Example data filters (uncomment to use):
					// DataFilters: []string{"pathname=/bin/bash"},        // Only execve of /bin/bash
					// DataFilters: []string{"pathname=/usr/bin/python*"}, // Only execve of python binaries
					// DataFilters: []string{"pathname!=/usr/*"},          // Exclude execve from /usr/

					// Example event version constraints (uncomment to use):
					// MinVersion: &v1beta1.Version{Major: 1, Minor: 2, Patch: 0}, // Requires execve v1.2.0+
					// MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0}, // Works up to execve v2.0.0 (exclusive)
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       detection.DataStoreContainer,
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       detection.DataStoreSystem,
					Dependency: detection.DependencyOptional,
				},
			},
			// Enrichments: []detection.EnrichmentRequirement{
			// 	{
			// 		Name:       detection.EnrichmentEnvironment,
			// 		Dependency: detection.DependencyRequired, // Detector requires env vars
			// 	},
			// 	{
			// 		Name:       detection.EnrichmentExecutableHash,
			// 		Dependency: detection.DependencyOptional, // Detector works without hashes
			// 		// Config:  detection.ExecutableHashConfigInode, // Uncomment to require specific hash mode
			// 	},
			// 	{
			// 		Name:       detection.EnrichmentContainer,
			// 		Dependency: detection.DependencyRequired, // Detector needs container fields in Event
			// 	},
			// },
			// Architectures: []string{"amd64"}, // Uncomment to restrict to amd64 (x86-64) only
			// Example: Only load on Tracee 0.20.0+
			// MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
			// Example: Only load on Tracee < 1.0.0
			// MaxTraceeVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
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
				{
					Name: "system_arch",
					Type: "const char*",
				},
				{
					Name: "kernel_version",
					Type: "const char*",
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
		// AutoPopulate declaratively specifies what the engine enriches automatically
		// - Threat: Copy ThreatMetadata to output event's Threat field (no manual cloning needed)
		// - DetectedFrom: Populate reference to the input event that triggered this detection
		// - ProcessAncestry: Query process store and add up to 5 ancestors to event.Workload.Process.Ancestors
		//                    Ancestors will show the process lineage (parent, grandparent, etc.)
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true, // Copy threat metadata from detector definition
			DetectedFrom:    true, // Reference to input event
			ProcessAncestry: true, // Automatically enrich with process lineage (5 levels)
		},
	}
}

func (d *ExampleDetector) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores

	// Log system info if available
	// Note: System datastore is optional, but registry always returns non-nil store
	// Check IsAvailable() or just use it directly (unavailable stores return empty/default values)
	systemStore := d.dataStores.System()
	sysInfo := systemStore.GetSystemInfo()
	d.logger.Debugw("ExampleDetector initialized with system info",
		"arch", sysInfo.Architecture,
		"kernel", sysInfo.KernelRelease,
		"os", sysInfo.OSPrettyName,
		"hostname", sysInfo.Hostname,
		"tracee_version", sysInfo.TraceeVersion)

	return nil
}

func (d *ExampleDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// This is a demonstration detector - it triggers on all execve events
	// Real detectors would have actual detection logic here
	if event.Name != "execve" {
		return nil, nil
	}

	// Get basic process information from the event
	binaryPath := event.GetWorkload().GetProcess().GetExecutable().GetPath()
	pid := event.GetWorkload().GetProcess().GetPid().GetValue()

	// Enrich with container information using ContainerStore
	// Note: This detector queries the datastore (Option 2 from docs)
	// Container enrichment (--enrichment container) is required for BOTH options:
	//   Option 1: Read Event.Workload.Container fields directly (simpler)
	//   Option 2: Query datastore (shown here, more flexible error handling)
	// Without enrichment, both Event fields and datastore will only have Container.Id
	containerID := event.GetWorkload().GetContainer().GetId()
	containerName := ""
	containerImage := ""

	// Get additional container details from ContainerStore
	// Note: Container datastore is marked as required, so it's always available
	if containerID != "" {
		containerStore := d.dataStores.Containers()
		containerInfo, err := containerStore.GetContainer(containerID)
		if err != nil {
			// Use errors.Is to distinguish between not-found vs actual errors
			if errors.Is(err, datastores.ErrNotFound) {
				// Container not in datastore cache - this is normal for short-lived containers
				d.logger.Debugw("Container not found in datastore cache", "container_id", containerID)
			} else {
				// Unexpected error querying datastore
				d.logger.Warnw("Failed to query container datastore",
					"error", err,
					"container_id", containerID)
			}
		} else {
			// Successfully enriched with container info
			containerName = containerInfo.Name
			containerImage = containerInfo.Image
			d.logger.Debugw("Enriched with container info",
				"container_id", containerID,
				"container_name", containerName,
				"image_name", containerImage)
		}
	}

	d.logger.Debugw("ExampleDetector triggered",
		"event_name", event.Name,
		"binary_path", binaryPath,
		"pid", pid,
		"container_id", containerID,
		"container_name", containerName)

	// Create output data with enriched field data
	var data []*v1beta1.EventValue

	// Always include binary path if available
	if binaryPath != "" {
		data = append(data, v1beta1.NewStringValue("binary_path", binaryPath))
	}

	// Add container information if event is from a container
	if containerID != "" {
		data = append(data, v1beta1.NewStringValue("container_id", containerID))
		// Include enriched container details if available
		if containerName != "" {
			data = append(data, v1beta1.NewStringValue("container_name", containerName))
		}
		if containerImage != "" {
			data = append(data, v1beta1.NewStringValue("container_image", containerImage))
		}
	}

	// Add detection metadata
	data = append(data,
		v1beta1.NewStringValue("detection_reason", "Example detection - all execve events with DataStore enrichment"),
		v1beta1.NewInt32Value("confidence", 100),
	)

	// Add system information (optional datastore, but always available via registry)
	systemStore := d.dataStores.System()
	sysInfo := systemStore.GetSystemInfo()
	if sysInfo.Architecture != "" {
		data = append(data,
			v1beta1.NewStringValue("system_arch", sysInfo.Architecture),
			v1beta1.NewStringValue("kernel_version", sysInfo.KernelRelease),
		)
	}

	return detection.DetectedWithData(data), nil
}

func (d *ExampleDetector) Close() error {
	d.logger.Debugw("ExampleDetector closed")
	return nil
}
