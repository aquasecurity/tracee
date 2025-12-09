package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&SudoersModification{})
}

// SudoersModification detects modifications to sudoers configuration files.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type SudoersModification struct {
	logger detection.Logger
}

func (d *SudoersModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1028",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"pathname=/etc/sudoers",
						"pathname=/private/etc/sudoers",
						"pathname=/etc/sudoers.d/*",
						"pathname=/private/etc/sudoers.d/*",
					},
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"new_path=/etc/sudoers",
						"new_path=/private/etc/sudoers",
						"new_path=/etc/sudoers.d/*",
						"new_path=/private/etc/sudoers.d/*",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sudoers_modification",
			Description: "The sudoers file was modified",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Sudoers file modification detected",
			Description: "The sudoers file was modified. The sudoers file is a configuration file which controls the permissions and options of the sudo feature. Adversaries may alter the sudoers file to elevate privileges, execute commands as other users or spawn processes with higher privileges.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Privilege Escalation"},
				Technique: &v1beta1.MitreTechnique{Id: "T1548.003", Name: "Sudo and Sudo Caching"},
			},
			Properties: map[string]string{"Category": "privilege-escalation"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *SudoersModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("SudoersModification detector initialized")
	return nil
}

func (d *SudoersModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name

	switch eventName {
	case "security_file_open":
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileWrite(int(flags)) {
			return nil, nil
		}

		// DataFilter already validated pathname is a sudoers file
		pathname, _ := v1beta1.GetDataSafe[string](event, "pathname")
		d.logger.Debugw("Sudoers file modification detected", "path", pathname)
		return detection.Detected(), nil

	case "security_inode_rename":
		// DataFilter already validated new_path is a sudoers file
		newPath, _ := v1beta1.GetDataSafe[string](event, "new_path")
		d.logger.Debugw("Sudoers file modification detected", "path", newPath)
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *SudoersModification) Close() error {
	d.logger.Debugw("SudoersModification detector closed")
	return nil
}
