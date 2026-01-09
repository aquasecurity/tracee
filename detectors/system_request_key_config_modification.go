package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&SystemRequestKeyConfigModification{})
}

// SystemRequestKeyConfigModification detects modifications to sysrq configuration files.
// Adversaries may use this to control system behavior or gather information for container escape.
type SystemRequestKeyConfigModification struct {
	logger detection.Logger
}

func (d *SystemRequestKeyConfigModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1031",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_file_open",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
					DataFilters: []string{
						"pathname=/proc/sys/kernel/sysrq",
						"pathname=/proc/sysrq-trigger",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "system_request_key_mod",
			Description: "System request key configuration modification",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "System request key configuration modification",
			Description: "An attempt to modify and activate the System Request Key configuration file was detected. The system request key allows immediate input to the kernel through simple key combinations. Adversaries may use this feature to immediately shut down or restart a system. With read access to kernel logs, host related information such as listing tasks and CPU registers may be disclosed and could be used for container escape.",
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

func (d *SystemRequestKeyConfigModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("SystemRequestKeyConfigModification detector initialized")
	return nil
}

func (d *SystemRequestKeyConfigModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}

	if !parsers.IsFileWrite(int(flags)) {
		return nil, nil
	}

	d.logger.Debugw("sysrq modification detected", "container", v1beta1.GetContainerID(event))
	return detection.Detected(), nil
}

func (d *SystemRequestKeyConfigModification) Close() error {
	d.logger.Debugw("SystemRequestKeyConfigModification detector closed")
	return nil
}
