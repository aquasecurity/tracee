package detectors

import (
	"context"
	"path/filepath"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&CgroupNotifyOnReleaseModification{})
}

// CgroupNotifyOnReleaseModification detects modifications to cgroup notify_on_release files.
// Adversaries may use this feature for container escaping.
type CgroupNotifyOnReleaseModification struct {
	logger         detection.Logger
	notifyFileName string
}

func (d *CgroupNotifyOnReleaseModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-106",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// CRITICAL: Use container=started to match old Origin: "container" behavior
					ScopeFilters: []string{"container=started"},
					// No DataFilters - need to check basename of pathname
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "cgroup_notify_on_release",
			Description: "Cgroups notify_on_release file modification",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Cgroups notify_on_release file modification",
			Description: "An attempt to modify Cgroup notify_on_release file was detected. Cgroups are a Linux kernel feature which limits the resource usage of a set of processes. Adversaries may use this feature for container escaping.",
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

func (d *CgroupNotifyOnReleaseModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.notifyFileName = "notify_on_release"
	d.logger.Debugw("CgroupNotifyOnReleaseModification detector initialized")
	return nil
}

func (d *CgroupNotifyOnReleaseModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		d.logger.Debugw("Failed to extract pathname", "error", err)
		return nil, nil
	}

	// Check if basename is notify_on_release
	basename := filepath.Base(pathname)
	if basename != d.notifyFileName {
		return nil, nil
	}

	// Extract flags
	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		d.logger.Debugw("Failed to extract flags", "error", err)
		return nil, nil
	}

	// Check if it's a write operation
	if !parsers.IsFileWrite(int(flags)) {
		return nil, nil
	}

	// Detection: notify_on_release modification from container
	d.logger.Debugw("notify_on_release modification detected",
		"path", pathname,
		"container", v1beta1.GetContainerID(event))

	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *CgroupNotifyOnReleaseModification) Close() error {
	d.logger.Debugw("CgroupNotifyOnReleaseModification detector closed")
	return nil
}
