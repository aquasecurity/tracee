//go:build e2e

package e2e

import (
	"context"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/environment"
)

func init() { registerE2e(&E2eProcessExecuteFailed{}) }

// E2eProcessExecuteFailed is an e2e test detector for testing the process_execute_failed event.
type E2eProcessExecuteFailed struct {
	logger                detection.Logger
	osInfo                *environment.OSInfo
	markUnsupportedKernel sync.Once
	unsupportedKernel     bool
}

func (d *E2eProcessExecuteFailed) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "PROCESS_EXECUTE_FAILED",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "process_execute_failed",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "init_namespaces",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "PROCESS_EXECUTE_FAILED",
			Description: "Instrumentation events E2E Tests: Process Execute Failed",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eProcessExecuteFailed) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	var err error
	d.osInfo, err = environment.GetOSInfo()
	if err != nil {
		return err
	}
	d.unsupportedKernel = false
	d.logger.Debugw("E2eProcessExecuteFailed detector initialized")
	return nil
}

func (d *E2eProcessExecuteFailed) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	switch event.Name {
	case "init_namespaces":
		// The event is not guaranteed to work for kernel version 5.7 or older, making the test
		// unreliable. Ensure that the tests will pass (unless an error occur).
		var detectionOutput []detection.DetectorOutput
		d.markUnsupportedKernel.Do(func() {
			comp, err := d.osInfo.CompareOSBaseKernelRelease("5.7")
			if err != nil {
				return
			}
			if comp == environment.KernelVersionNewer { // < V5.8
				d.unsupportedKernel = true
				detectionOutput = detection.Detected()
			}
		})
		if detectionOutput != nil {
			return detectionOutput, nil
		}

	case "process_execute_failed":
		filePath, err := v1beta1.GetDataSafe[string](event, "pathname")
		if err != nil {
			return nil, nil
		}

		// Check expected values from test for detection
		if !strings.HasSuffix(filePath, "test.sh") {
			return nil, nil
		}

		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *E2eProcessExecuteFailed) Close() error {
	d.logger.Debugw("E2eProcessExecuteFailed detector closed")
	return nil
}
