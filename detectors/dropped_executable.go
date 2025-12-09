package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/elf"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&DroppedExecutable{})
}

// DroppedExecutable detects when an executable file is written in a container.
// Container images should have all binaries needed. A dropped binary may indicate infiltration.
type DroppedExecutable struct {
	logger detection.Logger
}

func (d *DroppedExecutable) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1022",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "magic_write",
					Dependency: detection.DependencyRequired,
					// CRITICAL: Use container=started to match old Origin: "container" behavior
					// This checks BOTH Container.ID != "" AND ContainerStarted == true
					ScopeFilters: []string{"container=started"},
					// No DataFilters - need to check ELF magic bytes and path runtime
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "dropped_executable",
			Description: "New executable dropped in container",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "path", Type: "string"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "New executable dropped",
			Description: "An Executable file was dropped in the system during runtime. Container images are usually built with all binaries needed inside. A dropped binary may indicate that an adversary infiltrated your container.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1036",
					Name: "Masquerading",
				},
			},
			Properties: map[string]string{
				"Category": "defense-evasion",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *DroppedExecutable) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("DroppedExecutable detector initialized")
	return nil
}

func (d *DroppedExecutable) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract magic bytes written
	bytes, ok := v1beta1.GetData[[]byte](event, "bytes")
	if !ok {
		d.logger.Debugw("Failed to extract bytes")
		return nil, nil
	}

	// Check if it's an ELF file
	if !elf.IsElf(bytes) {
		return nil, nil
	}

	// Extract pathname
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		d.logger.Debugw("Failed to extract pathname", "error", err)
		return nil, nil
	}

	// Ignore memory paths (e.g., memfd:, /dev/shm/)
	if parsers.IsMemoryPath(pathname) {
		return nil, nil
	}

	// Detection: ELF executable dropped to disk in container
	d.logger.Debugw("Executable dropped in container",
		"path", pathname,
		"container", v1beta1.GetContainerID(event))

	return []detection.DetectorOutput{{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("path", pathname),
		},
	}}, nil
}

func (d *DroppedExecutable) Close() error {
	d.logger.Debugw("DroppedExecutable detector closed")
	return nil
}
