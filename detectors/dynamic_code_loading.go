package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&DynamicCodeLoading{})
}

const (
	// Memory protection alert types (from types/trace/trace.go)
	protAlertMprotectWXToX = 4 // Protection changed from W+X to X
)

// DynamicCodeLoading detects when memory is changed from W+E to X (write+execute to execute-only).
// Adversaries use this technique to write code into writable+executable memory and then execute it.
type DynamicCodeLoading struct {
	logger detection.Logger
}

func (d *DynamicCodeLoading) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-104",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "mem_prot_alert",
					Dependency: detection.DependencyRequired,
					// Filter for ProtAlertMprotectWXToX (4) - memory protection changed from W+X to X
					// This indicates code was written to writable+executable memory
					DataFilters: []string{
						"alert=4",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "dynamic_code_loading",
			Description: "Dynamic code loading detected via memory protection change",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Dynamic code loading detected",
			Description: "Possible dynamic code loading was detected as the binary's memory is both writable and executable. Writing to an executable allocated memory region could be a technique used by adversaries to run code undetected and without dropping executables.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1027.002",
					Name: "Software Packing",
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

func (d *DynamicCodeLoading) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("DynamicCodeLoading detector initialized")
	return nil
}

func (d *DynamicCodeLoading) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// If we received this event, the data filter matched (alert=ProtAlertMprotectWXToX)
	// This means memory protection changed from writable+executable to executable-only
	// indicating code was likely written and is now being executed
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *DynamicCodeLoading) Close() error {
	d.logger.Debugw("DynamicCodeLoading detector closed")
	return nil
}
