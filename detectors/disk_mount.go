package detectors

import (
	"context"

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
}

func (d *DiskMount) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1014",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_sb_mount",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
					DataFilters:  []string{"dev_name=/dev/*"},
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
	d.logger.Debugw("DiskMount detector initialized")
	return nil
}

func (d *DiskMount) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// DataFilter ensures dev_name starts with /dev/ - detection confirmed
	d.logger.Debugw("Container device mount detected",
		"container", v1beta1.GetContainerID(event))

	return detection.Detected(), nil
}

func (d *DiskMount) Close() error {
	d.logger.Debugw("DiskMount detector closed")
	return nil
}
