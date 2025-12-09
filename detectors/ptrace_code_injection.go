package detectors

import (
	"context"
	"fmt"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&PtraceCodeInjection{})
}

// PtraceCodeInjection detects code injection using ptrace POKETEXT/POKEDATA operations.
// Adversaries use ptrace to write code into another process's memory for code injection.
type PtraceCodeInjection struct {
	logger detection.Logger
}

func (d *PtraceCodeInjection) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-103",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "ptrace",
					Dependency: detection.DependencyRequired,
					// Filter for PTRACE_POKETEXT (4) or PTRACE_POKEDATA (5)
					// These operations write to another process's memory
					DataFilters: []string{
						fmt.Sprintf("request=%d", parsers.PTRACE_POKETEXT.Value()),
						fmt.Sprintf("request=%d", parsers.PTRACE_POKEDATA.Value()),
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "ptrace_code_injection",
			Description: "Code injection using ptrace detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Code injection detected using ptrace",
			Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1055.008",
					Name: "Ptrace System Calls",
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

func (d *PtraceCodeInjection) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("PtraceCodeInjection detector initialized")
	return nil
}

func (d *PtraceCodeInjection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// If we received this event, the data filter matched (request=PTRACE_POKETEXT or PTRACE_POKEDATA)
	// These operations write to another process's memory, indicating potential code injection
	// No additional data to extract - detection is the presence of the event itself
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *PtraceCodeInjection) Close() error {
	d.logger.Debugw("PtraceCodeInjection detector closed")
	return nil
}
