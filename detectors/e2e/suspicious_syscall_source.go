//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSuspiciousSyscallSource{}) }

// E2eSuspiciousSyscallSource is an e2e test detector for testing the suspicious_syscall_source event.
type E2eSuspiciousSyscallSource struct {
	logger           detection.Logger
	foundMainStack   bool
	foundHeap        bool
	foundAnonVma     bool
	foundThreadStack bool
}

func (d *E2eSuspiciousSyscallSource) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SUSPICIOUS_SYSCALL_SOURCE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "suspicious_syscall_source",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SUSPICIOUS_SYSCALL_SOURCE",
			Description: "Instrumentation events E2E Tests: Suspicious Syscall Source",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSuspiciousSyscallSource) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.foundMainStack = false
	d.foundHeap = false
	d.foundAnonVma = false
	d.foundThreadStack = false
	d.logger.Debugw("E2eSuspiciousSyscallSource detector initialized")
	return nil
}

func (d *E2eSuspiciousSyscallSource) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	syscall, err := v1beta1.GetDataSafe[string](event, "syscall")
	if err != nil {
		return nil, nil
	}

	vmaType, err := v1beta1.GetDataSafe[string](event, "vma_type")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if syscall != "exit" {
		return nil, nil
	}

	switch vmaType {
	case "main stack":
		d.foundMainStack = true
	case "heap":
		d.foundHeap = true
	case "anonymous":
		d.foundAnonVma = true
	case "thread stack":
		d.foundThreadStack = true
	default:
		return nil, nil
	}

	if !d.foundMainStack || !d.foundHeap || !d.foundAnonVma || !d.foundThreadStack {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eSuspiciousSyscallSource) Close() error {
	d.logger.Debugw("E2eSuspiciousSyscallSource detector closed")
	return nil
}
