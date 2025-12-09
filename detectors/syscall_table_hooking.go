package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&SyscallTableHooking{})
}

// SyscallTableHooking detects syscall table hooking (rootkit behavior).
// Origin: "*" (triggers on both host and containers - no container=started filter).
type SyscallTableHooking struct {
	logger detection.Logger
}

func (d *SyscallTableHooking) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1030",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "hooked_syscall",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "syscall_hooking",
			Description: "Syscall table hooking detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Syscall table hooking detected",
			Description: "Syscall table hooking detected. Syscalls (system calls) are the interface between user applications and the kernel. By hooking the syscall table an adversary gains control on certain system function, such as file writing and reading or other basic function performed by the operation system. The adversary may also hijack the execution flow and execute it's own code. Syscall table hooking is considered a malicious behavior that is performed by rootkits and may indicate that the host's kernel has been compromised. Hidden modules are marked as hidden symbol owners and indicate further malicious activity of an adversary.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Defense Evasion"},
				Technique: &v1beta1.MitreTechnique{Id: "T1014", Name: "Rootkit"},
			},
			Properties: map[string]string{"Category": "defense-evasion"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *SyscallTableHooking) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("SyscallTableHooking detector initialized")
	return nil
}

func (d *SyscallTableHooking) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Every hooked_syscall event is a detection
	d.logger.Debugw("Syscall table hooking detected")
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *SyscallTableHooking) Close() error {
	d.logger.Debugw("SyscallTableHooking detector closed")
	return nil
}
