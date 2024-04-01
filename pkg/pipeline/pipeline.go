package pipeline

import (
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type Data struct {
	utils.Cloner

	Event *trace.Event
	// Policies              *policy.Policies
	Policies              unsafe.Pointer
	MatchedPoliciesKernel uint64
	MatchedPoliciesUser   uint64
}

func (d *Data) Clone() *Data {
	event := *d.Event

	return &Data{
		// 'Event' is a pointer to a mutable struct, but we only need a shallow
		// copy due to performance reasons. Be aware of this when modifying
		// its referenced fields.
		Event:                 &event,                  // mutable
		Policies:              d.Policies,              // immutable
		MatchedPoliciesKernel: d.MatchedPoliciesKernel, // immutable
		MatchedPoliciesUser:   d.MatchedPoliciesUser,   // mutable
	}
}

type Protocol struct {
	utils.Cloner

	Event                 protocol.Event
	Policies              unsafe.Pointer
	MatchedPoliciesKernel uint64
	MatchedPoliciesUser   uint64
}

func (p *Protocol) Clone() *Protocol {
	return &Protocol{
		Event:                 p.Event,                 // immutable
		Policies:              p.Policies,              // immutable
		MatchedPoliciesKernel: p.MatchedPoliciesKernel, // immutable
		MatchedPoliciesUser:   p.MatchedPoliciesUser,   // mutable
	}
}

type Finding struct {
	utils.Cloner

	Finding               *detect.Finding
	Policies              unsafe.Pointer
	MatchedPoliciesKernel uint64
	MatchedPoliciesUser   uint64
}
