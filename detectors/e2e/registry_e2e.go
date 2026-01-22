//go:build e2e

package e2e

import (
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// e2eDetectors holds all non-network e2e detectors registered via init().
var e2eDetectors []detection.EventDetector

// registerE2e registers a detector with the e2e registry.
// Called by detector init() functions.
func registerE2e(d detection.EventDetector) {
	e2eDetectors = append(e2eDetectors, d)
}

// GetE2eDetectors returns all non-network e2e detectors.
// These are compiled with the "e2e" build tag.
func GetE2eDetectors() []detection.EventDetector {
	return e2eDetectors
}
