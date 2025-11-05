package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&AntiDebugging{})
}

// AntiDebugging detects anti-debugging techniques using PTRACE_TRACEME.
// Malware uses this to block debuggers and evade analysis.
type AntiDebugging struct {
	logger detection.Logger
}

func (d *AntiDebugging) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-102",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:        "ptrace",
					Dependency:  detection.DependencyRequired,
					DataFilters: []string{"request=0"}, // PTRACE_TRACEME
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "anti_debugging_detector",
			Description: "A process used anti-debugging techniques to block a debugger",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Anti-Debugging detected",
			Description: "A process used anti-debugging techniques to block a debugger. Malware use anti-debugging to stay invisible and inhibit analysis of their behavior.",
			Severity:    v1beta1.Severity_LOW,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1622",
					Name: "Debugger Evasion",
				},
			},
			Properties: map[string]string{
				"Category": "defense-evasion",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *AntiDebugging) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("AntiDebugging detector initialized")
	return nil
}

func (d *AntiDebugging) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// If we received this event, it means the data filter matched (request=0/PTRACE_TRACEME)
	// No data to extract - detection is the presence of the event itself
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *AntiDebugging) Close() error {
	d.logger.Debugw("AntiDebugging detector closed")
	return nil
}
