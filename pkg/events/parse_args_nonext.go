//go:build !extended

package events

import (
	"github.com/aquasecurity/tracee/types/trace"
)

// parseArgsExtended is a stub for non-extended builds
// In extended builds, this is replaced
func parseArgsExtended(eventID ID, args []trace.Argument) {
	// No-op for non-extended builds
}
