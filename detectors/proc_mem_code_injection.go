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
	register(&ProcMemCodeInjection{})
}

// ProcMemCodeInjection detects write access to /proc/*/mem files (code injection).
// Origin: "*" (triggers on both host and containers - no container=started filter).
type ProcMemCodeInjection struct {
	logger        detection.Logger
	compiledRegex *regexp.Regexp
}

const procMemCodeInjectionPattern = `/proc/(?:\d+|self)/mem$`

func (d *ProcMemCodeInjection) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1024",
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
			Name:        "proc_mem_code_injection",
			Description: "Code injection detected through /proc/<pid>/mem file",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Code injection detected through /proc/<pid>/mem file",
			Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Defense Evasion"},
				Technique: &v1beta1.MitreTechnique{Id: "T1055.009", Name: "Proc Memory"},
			},
			Properties: map[string]string{"Category": "defense-evasion"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *ProcMemCodeInjection) Init(params detection.DetectorParams) error {
	var err error
	d.logger = params.Logger
	d.compiledRegex, err = regexp.Compile(procMemCodeInjectionPattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %w", err)
	}
	d.logger.Debugw("ProcMemCodeInjection detector initialized")
	return nil
}

func (d *ProcMemCodeInjection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}

	if parsers.IsFileWrite(int(flags)) && d.compiledRegex.MatchString(pathname) {
		d.logger.Debugw("Process memory code injection detected", "path", pathname)
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *ProcMemCodeInjection) Close() error {
	d.logger.Debugw("ProcMemCodeInjection detector closed")
	return nil
}
