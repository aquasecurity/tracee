//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	registerE2e(&E2eBpfAttach{})
}

// E2eBpfAttach is an e2e test detector for testing the bpf_attach event.
type E2eBpfAttach struct {
	logger detection.Logger
}

func (d *E2eBpfAttach) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "BPF_ATTACH",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "bpf_attach",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "BPF_ATTACH",
			Description: "Instrumentation events E2E Tests: Bpf Attach",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eBpfAttach) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eBpfAttach detector initialized")
	return nil
}

func (d *E2eBpfAttach) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	symbolName, err := v1beta1.GetDataSafe[string](event, "symbol_name")
	if err != nil {
		return nil, nil
	}

	attachType, err := v1beta1.GetDataSafe[int32](event, "attach_type")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if symbolName != "security_file_open" || attachType != int32(parsers.BPFProgTypeKprobe) {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eBpfAttach) Close() error {
	d.logger.Debugw("E2eBpfAttach detector closed")
	return nil
}
