//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSignatureDerivation{}) }

// E2eSignatureDerivation is an e2e test detector that tests signature/detector derivation.
// It listens for the FILE_MODIFICATION event (produced by another detector) and emits its own event.
type E2eSignatureDerivation struct {
	logger detection.Logger
}

func (d *E2eSignatureDerivation) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SIGNATURE_DERIVATION",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					// Listen for events from another detector
					Name:       "FILE_MODIFICATION",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SIGNATURE_DERIVATION",
			Description: "Instrumentation events E2E Tests: Signature Derivation",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSignatureDerivation) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eSignatureDerivation detector initialized")
	return nil
}

func (d *E2eSignatureDerivation) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// This detector receives FILE_MODIFICATION events from another detector
	// and produces its own SIGNATURE_DERIVATION event
	return detection.Detected(), nil
}

func (d *E2eSignatureDerivation) Close() error {
	d.logger.Debugw("E2eSignatureDerivation detector closed")
	return nil
}
