package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&DiskMount{})
}

// DiskMount detects when a container mounts a host device filesystem.
// This can be exploited by adversaries to perform container escape.
type DiskMount struct {
	logger detection.Logger
	devDir string
}

func (d *DiskMount) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1014",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_sb_mount",
					Dependency: detection.DependencyRequired,
					// CRITICAL: Use container=started to match old Origin: "container" behavior
					// This checks BOTH Container.ID != "" AND ContainerStarted == true
					ScopeFilters: []string{"container=started"},
					// No DataFilters - need to check if dev_name starts with /dev/
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "disk_mount",
			Description: "Container device mount detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Container device mount detected",
			Description: "Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Privilege Escalation",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1611",
					Name: "Escape to Host",
				},
			},
			Properties: map[string]string{
				"Category": "privilege-escalation",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *DiskMount) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.devDir = "/dev/"
	d.logger.Debugw("DiskMount detector initialized")
	return nil
}

func (d *DiskMount) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract device name from mount event
	deviceName, err := v1beta1.GetDataSafe[string](event, "dev_name")
	if err != nil {
		d.logger.Debugw("Failed to extract dev_name", "error", err)
		return nil, nil
	}

	// Check if device is being mounted from /dev/ (host device)
	if !strings.HasPrefix(deviceName, d.devDir) {
		return nil, nil
	}

	// Detection: container mounting host device
	d.logger.Debugw("Container device mount detected",
		"device", deviceName,
		"container", v1beta1.GetContainerID(event))

	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *DiskMount) Close() error {
	d.logger.Debugw("DiskMount detector closed")
	return nil
}
