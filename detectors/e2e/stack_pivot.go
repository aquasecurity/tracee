//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eStackPivot{}) }

// E2eStackPivot is an e2e test detector for testing the stack_pivot event.
type E2eStackPivot struct {
	logger        detection.Logger
	falsePositive bool // Track if a false positive was detected
}

func (d *E2eStackPivot) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "STACK_PIVOT",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "stack_pivot",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "STACK_PIVOT",
			Description: "Instrumentation events E2E Tests: Stack Pivot",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eStackPivot) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.falsePositive = false
	d.logger.Debugw("E2eStackPivot detector initialized")
	return nil
}

func (d *E2eStackPivot) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	syscall, err := v1beta1.GetDataSafe[string](event, "syscall")
	if err != nil {
		return nil, nil
	}

	vmaType, err := v1beta1.GetDataSafe[string](event, "vma_type")
	if err != nil {
		return nil, nil
	}

	// Get process name from workload
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		processName = event.Workload.Process.Thread.Name
	}

	// Make sure this is the exact event we're looking for
	if processName == "stack_pivot" && syscall == "exit_group" && vmaType == "heap" {
		// Make sure there was no false positive
		if !d.falsePositive {
			return detection.Detected(), nil
		}
	} else {
		// False positive, mark it so that the test will fail
		d.falsePositive = true
		d.logger.Warnw("False positive detected", "process", processName, "syscall", syscall, "vma_type", vmaType)
	}

	return nil, nil
}

func (d *E2eStackPivot) Close() error {
	d.logger.Debugw("E2eStackPivot detector closed")
	return nil
}
