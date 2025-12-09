package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&ProcessVmWriteCodeInjection{})
}

// ProcessVmWriteCodeInjection detects code injection using process_vm_writev syscall.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type ProcessVmWriteCodeInjection struct {
	logger detection.Logger
}

func (d *ProcessVmWriteCodeInjection) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1025",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "process_vm_writev",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "process_vm_write_inject",
			Description: "Code injection detected using process_vm_writev syscall",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Code injection detected using process_vm_writev syscall",
			Description: "Possible code injection into another process was detected. Code injection is an exploitation technique used to run malicious code, adversaries may use it in order to execute their malware.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Defense Evasion"},
				Technique: &v1beta1.MitreTechnique{Id: "T1055", Name: "Process Injection"},
			},
			Properties: map[string]string{"Category": "defense-evasion"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *ProcessVmWriteCodeInjection) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("ProcessVmWriteCodeInjection detector initialized")
	return nil
}

func (d *ProcessVmWriteCodeInjection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Check if writing to a different process
	dstPid, err := v1beta1.GetDataSafe[int32](event, "pid")
	if err != nil {
		return nil, nil
	}

	// Get current process ID from workload
	var currentPid int32
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Pid != nil {
		currentPid = int32(event.Workload.Process.Pid.Value)
	}

	if currentPid != dstPid {
		d.logger.Debugw("Process VM write code injection detected", "src_pid", currentPid, "dst_pid", dstPid)
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *ProcessVmWriteCodeInjection) Close() error {
	d.logger.Debugw("ProcessVmWriteCodeInjection detector closed")
	return nil
}
