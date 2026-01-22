//go:build e2e

package detectors

import (
	"github.com/aquasecurity/tracee/detectors/e2e"
)

func init() {
	// Register all non-network e2e detectors with the main registry.
	for _, d := range e2e.GetE2eDetectors() {
		register(d)
	}
}
