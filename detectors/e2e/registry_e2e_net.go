//go:build e2e_net

package e2e

import (
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// e2eNetDetectors holds all network e2e detectors registered via init().
var e2eNetDetectors []detection.EventDetector

// registerE2eNet registers a detector with the e2e_net registry.
// Called by detector init() functions.
func registerE2eNet(d detection.EventDetector) {
	e2eNetDetectors = append(e2eNetDetectors, d)
}

// GetE2eNetDetectors returns all network e2e detectors.
// These are compiled with the "e2e_net" build tag.
func GetE2eNetDetectors() []detection.EventDetector {
	return e2eNetDetectors
}
