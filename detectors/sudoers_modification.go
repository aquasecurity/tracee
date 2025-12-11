package detectors

import (
	"context"
	"strings"

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
	logger       detection.Logger
	sudoersFiles map[string]bool
	sudoersDirs  []string
}

func (d *SudoersModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1028",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
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
	d.sudoersFiles = map[string]bool{
		"/etc/sudoers":         true,
		"/private/etc/sudoers": true,
	}
	d.sudoersDirs = []string{"/etc/sudoers.d/", "/private/etc/sudoers.d/"}
	d.logger.Debugw("SudoersModification detector initialized")
	return nil
}

func (d *SudoersModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name
	var path string

	switch eventName {
	case "security_file_open":
		pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
		if err != nil {
			return nil, nil
		}

		// Check if it's a write operation (matching original signature logic)
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileWrite(int(flags)) {
			return nil, nil
		}

		path = pathname
	case "security_inode_rename":
		newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
		if err != nil {
			return nil, nil
		}
		path = newPath
	default:
		return nil, nil
	}

	// Check if path matches sudoers files
	if d.sudoersFiles[path] {
		d.logger.Debugw("Sudoers file modification detected", "path", path)
		return []detection.DetectorOutput{{Data: nil}}, nil
	}

	// Check if path is within sudoers.d directories
	for _, dir := range d.sudoersDirs {
		if strings.HasPrefix(path, dir) {
			d.logger.Debugw("Sudoers directory file modification detected", "path", path)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	}

	return nil, nil
}

func (d *SudoersModification) Close() error {
	d.logger.Debugw("SudoersModification detector closed")
	return nil
}
