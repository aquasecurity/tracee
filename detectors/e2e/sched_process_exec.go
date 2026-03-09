//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSchedProcessExec{}) }

// E2eSchedProcessExec is an e2e test detector for testing the sched_process_exec event.
type E2eSchedProcessExec struct {
	logger detection.Logger
}

func (d *E2eSchedProcessExec) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SCHED_PROCESS_EXEC",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SCHED_PROCESS_EXEC",
			Description: "Instrumentation events E2E Tests: sched_process_exec",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSchedProcessExec) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eSchedProcessExec detector initialized")
	return nil
}

func (d *E2eSchedProcessExec) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Validate prev_comm field is correctly populated after task rename
	prevComm, err := v1beta1.GetDataSafe[string](event, "prev_comm")
	if err != nil {
		return nil, nil
	}

	// Check if this is our test case - prev_comm should be "e2e_rename_test"
	if prevComm != "e2e_rename_test" {
		return nil, nil
	}

	// Verify we're executing the expected program
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		processName = event.Workload.Process.Thread.Name
	}

	if processName != "true" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eSchedProcessExec) Close() error {
	d.logger.Debugw("E2eSchedProcessExec detector closed")
	return nil
}
