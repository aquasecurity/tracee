package types

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// Event wrappers a pb.Event with additional metadata
type Event struct {
	*pb.Event
	PoliciesVersion       uint16 `json:"-"`
	MatchedPoliciesKernel uint64 `json:"-"`
	MatchedPoliciesUser   uint64 `json:"-"`
}

func (e *Event) Proto() *pb.Event {
	return e.Event
}
