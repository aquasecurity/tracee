//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eHookedSyscall{}) }

// E2eHookedSyscall is an e2e test detector for testing the hooked_syscall event.
type E2eHookedSyscall struct {
	logger detection.Logger
}

func (d *E2eHookedSyscall) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "HOOKED_SYSCALL",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "hooked_syscall",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "HOOKED_SYSCALL",
			Description: "Instrumentation events E2E Tests: Hooked Syscall",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eHookedSyscall) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eHookedSyscall detector initialized")
	return nil
}

func (d *E2eHookedSyscall) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	syscall, err := v1beta1.GetDataSafe[string](event, "syscall")
	if err != nil {
		return nil, nil
	}

	owner, err := v1beta1.GetDataSafe[string](event, "owner")
	if err != nil {
		return nil, nil
	}

	if syscall == "uname" && owner == "hijack" {
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *E2eHookedSyscall) Close() error {
	d.logger.Debugw("E2eHookedSyscall detector closed")
	return nil
}
