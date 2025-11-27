package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&ProcFopsHooking{})
}

// ProcFopsHooking detects file operations hooking on proc filesystem.
// Origin: "host" (host-only events - no container filter needed as it's kernel-level).
type ProcFopsHooking struct {
	logger detection.Logger
}

func (d *ProcFopsHooking) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1020",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "hooked_proc_fops",
					Dependency: detection.DependencyRequired,
					// Note: Origin "host" from original - kernel-level event
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "proc_fops_hooking_detector",
			Description: "File operations hooking on proc filesystem detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "File operations hooking on proc filesystem detected",
			Description: "File operations hooking on proc filesystem detected. The proc filesystem is an interface for the running processes as files. This allows programs like `ps` and `top` to check what are the running processes. File operations are the functions defined on a file or directory. File operations hooking includes replacing the default function used to perform a basic task on files and directories like enumerating files. By hooking the file operations of /proc an adversary gains control on certain system function, such as file listing or other basic function performed by the operation system. The adversary may also hijack the execution flow and execute it's own code. File operation hooking is considered a malicious behavior that is performed by rootkits and may indicate that the host's kernel has been compromised. Hidden modules are marked as hidden symbol owners and indicate further malicious activity of an adversary.",
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

func (d *ProcFopsHooking) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("ProcFopsHooking detector initialized")
	return nil
}

func (d *ProcFopsHooking) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Every hooked_proc_fops event is a detection
	d.logger.Warnw("Proc fops hooking detected")
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *ProcFopsHooking) Close() error {
	d.logger.Debugw("ProcFopsHooking detector closed")
	return nil
}
