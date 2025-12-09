package detectors

import (
	"context"
	"path/filepath"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&CgroupReleaseAgentModification{})
}

// CgroupReleaseAgentModification detects modifications to cgroup release_agent files.
// Adversaries may use this feature for container escaping.
type CgroupReleaseAgentModification struct {
	logger           detection.Logger
	releaseAgentName string
}

func (d *CgroupReleaseAgentModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1010",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_file_open",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
				},
				{
					Name:         "security_inode_rename",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "cgroup_release_agent",
			Description: "Cgroups release agent file modification",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Cgroups release agent file modification",
			Description: "An attempt to modify Cgroup release agent file was detected. Cgroups are a Linux kernel feature which limits the resource usage of a set of processes. Adversaries may use this feature for container escaping.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Privilege Escalation"},
				Technique: &v1beta1.MitreTechnique{Id: "T1611", Name: "Escape to Host"},
			},
			Properties: map[string]string{"Category": "privilege-escalation"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *CgroupReleaseAgentModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.releaseAgentName = "release_agent"
	d.logger.Debugw("CgroupReleaseAgentModification detector initialized")
	return nil
}

func (d *CgroupReleaseAgentModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	basename := ""

	switch event.Name {
	case "security_file_open":
		pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
		if err != nil {
			return nil, nil
		}
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}
		if parsers.IsFileWrite(int(flags)) {
			basename = filepath.Base(pathname)
		}
	case "security_inode_rename":
		newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
		if err != nil {
			return nil, nil
		}
		basename = filepath.Base(newPath)
	}

	if basename == d.releaseAgentName {
		d.logger.Debugw("release_agent modification detected", "container", v1beta1.GetContainerID(event))
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *CgroupReleaseAgentModification) Close() error {
	d.logger.Debugw("CgroupReleaseAgentModification detector closed")
	return nil
}
