package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&KernelModuleLoading{})
}

// KernelModuleLoading detects kernel module loading events.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type KernelModuleLoading struct {
	logger detection.Logger
}

func (d *KernelModuleLoading) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1017",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "module_load",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "kernel_module_loading",
			Description: "Loading of a kernel module was detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Kernel module loading detected",
			Description: "Loading of a kernel module was detected. Kernel modules are binaries meant to run in the kernel. Adversaries may try and load kernel modules to extend their capabilities and avoid detection by running in the kernel and not user space.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Persistence"},
				Technique: &v1beta1.MitreTechnique{Id: "T1547.006", Name: "Kernel Modules and Extensions"},
			},
			Properties: map[string]string{"Category": "persistence"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *KernelModuleLoading) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("KernelModuleLoading detector initialized")
	return nil
}

func (d *KernelModuleLoading) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Every module_load event is a detection
	d.logger.Debugw("Kernel module loading detected")
	return detection.Detected(), nil
}

func (d *KernelModuleLoading) Close() error {
	d.logger.Debugw("KernelModuleLoading detector closed")
	return nil
}
