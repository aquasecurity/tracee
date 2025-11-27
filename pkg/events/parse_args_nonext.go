//go:build !extended

package events

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// parseEventDataExtended is a stub for non-extended builds
// In extended builds, this is replaced
func parseEventDataExtended(eventID ID, data []*pb.EventValue) {
	// No-op for non-extended builds
}
