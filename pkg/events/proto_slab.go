package events

import (
	"sync"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// maxSlabArgs is the number of pre-allocated EventValue slots in the slab.
// Events with more args than this fall back to heap allocation for the excess.
const maxSlabArgs = 16

// eventSlab pools the parts of proto.Event conversion that no downstream
// consumer aliases past the slab's recycle point.
//
// Workload and its children (Process, Thread, User, Container, K8s, ancestor
// Process, the wrapperspb.UInt32 wrappers, thread.StartTime, etc.) are NOT
// pooled: detector outputs shallow-copy inputEvent.Workload (see
// pkg/detectors/dispatch.go buildEventFromOutput). Pooling Workload (or
// anything reachable from it) would let a recycled slab corrupt a still-in-
// flight detector output.
//
// What is pooled:
//   - the top-level pb.Event (its pointer fields point to heap objects)
//   - pb.Policies (written fresh by sink; never aliased)
//   - the EventValue array backing event.Data (detector outputs use the
//     detector's own Data, never the input's Data)
type eventSlab struct {
	event      pb.Event
	policies   pb.Policies
	dataValues [maxSlabArgs]pb.EventValue
	dataPtrs   [maxSlabArgs]*pb.EventValue // backing array for event.Data slice
}

func (s *eventSlab) reset() {
	s.event.Reset()
	s.policies.Reset()
	for i := range s.dataValues {
		s.dataValues[i].Reset()
		s.dataPtrs[i] = nil
	}
}

var protoSlabPool = sync.Pool{
	New: func() any { return new(eventSlab) },
}
