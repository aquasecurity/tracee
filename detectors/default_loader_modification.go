package detectors

import (
	"context"
	"regexp"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&DefaultLoaderModification{})
}

// DefaultLoaderModification detects modifications to the system's dynamic loader (ld.so).
// Origin: "*" (triggers on both host and containers - no container=started filter).
type DefaultLoaderModification struct {
	logger        detection.Logger
	compiledRegex *regexp.Regexp
}

const dynamicLoaderPattern = `^/(lib|usr/lib).*/ld.*\.so[^/]*`

func (d *DefaultLoaderModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1012",
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
			Name:        "default_loader_mod",
			Description: "The default dynamic loader has been modified",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Default dynamic loader modification detected",
			Description: "The default dynamic loader has been modified. The dynamic loader is an executable file loaded to process memory and run before the executable to load dynamic libraries to the process. An attacker might use this technique to hijack the execution context of each new process and bypass defenses.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Defense Evasion"},
				Technique: &v1beta1.MitreTechnique{Id: "T1574", Name: "Hijack Execution Flow"},
			},
			Properties: map[string]string{"Category": "defense-evasion"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *DefaultLoaderModification) Init(params detection.DetectorParams) error {
	var err error
	d.logger = params.Logger
	d.compiledRegex, err = regexp.Compile(dynamicLoaderPattern)
	if err != nil {
		return err
	}
	d.logger.Debugw("DefaultLoaderModification detector initialized")
	return nil
}

func (d *DefaultLoaderModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
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

	if d.compiledRegex.MatchString(path) {
		d.logger.Debugw("Dynamic loader modification detected", "path", path)
		return []detection.DetectorOutput{{Data: nil}}, nil
	}

	return nil, nil
}

func (d *DefaultLoaderModification) Close() error {
	d.logger.Debugw("DefaultLoaderModification detector closed")
	return nil
}
