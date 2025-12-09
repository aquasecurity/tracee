package detectors

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&ProcMemAccess{})
}

// ProcMemAccess detects read access to /proc/*/mem files.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type ProcMemAccess struct {
	logger        detection.Logger
	compiledRegex *regexp.Regexp
}

const procMemPathPattern = `/proc/(?:\d+|self)/mem$`

func (d *ProcMemAccess) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1023",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "proc_mem_access",
			Description: "Process memory access detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Process memory access detected",
			Description: "Process memory access detected. Adversaries may access other processes memory to steal credentials and secrets.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Credential Access"},
				Technique: &v1beta1.MitreTechnique{Id: "T1003.007", Name: "Proc Filesystem"},
			},
			Properties: map[string]string{"Category": "credential-access"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *ProcMemAccess) Init(params detection.DetectorParams) error {
	var err error
	d.logger = params.Logger
	d.compiledRegex, err = regexp.Compile(procMemPathPattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %w", err)
	}
	d.logger.Debugw("ProcMemAccess detector initialized")
	return nil
}

func (d *ProcMemAccess) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}

	if parsers.IsFileRead(int(flags)) && d.compiledRegex.MatchString(pathname) {
		d.logger.Debugw("Process memory access detected", "path", pathname)
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *ProcMemAccess) Close() error {
	d.logger.Debugw("ProcMemAccess detector closed")
	return nil
}
