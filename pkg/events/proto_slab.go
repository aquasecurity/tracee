package events

import (
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// maxSlabArgs is the number of pre-allocated EventValue slots in the slab.
// Events with more args than this will fall back to heap allocation for the excess.
const maxSlabArgs = 16

// eventSlab is a flat allocation containing all proto sub-objects needed for a single
// event conversion. By co-locating these objects in a single struct, we replace ~25
// individual heap allocations per event with a single slab allocation. When used with
// sync.Pool, filtered events recycle slabs with zero allocations after warmup.
type eventSlab struct {
	event          pb.Event
	workload       pb.Workload
	process        pb.Process
	thread         pb.Thread
	user           pb.User
	ancestor       pb.Process
	executable     pb.Executable
	container      pb.Container
	containerImage pb.ContainerImage
	k8s            pb.K8S
	k8sNamespace   pb.K8SNamespace
	pod            pb.Pod
	policies       pb.Policies
	userStackTrace pb.UserStackTrace

	// Pre-allocated wrappers (eliminates wrapperspb.UInt32() allocs).
	// Layout: [0-2]=thread(UniqueId,Tid,HostTid), [3-5]=process(Pid,HostPid,UniqueId),
	// [6]=user.Id, [7-9]=ancestor(UniqueId,HostPid,Pid), [10-13]=reserved
	uint32s [14]wrapperspb.UInt32Value

	// Pre-allocated timestamps: [0]=event timestamp, [1]=thread start time
	timestamps [2]timestamppb.Timestamp

	// Pre-allocated EventValue for up to maxSlabArgs args
	dataValues [maxSlabArgs]pb.EventValue
	dataPtrs   [maxSlabArgs]*pb.EventValue
}

// reset clears all fields so the slab can be reused from the pool.
// This zeroes pointer fields to avoid retaining stale references.
func (s *eventSlab) reset() {
	s.event.Reset()
	s.workload.Reset()
	s.process.Reset()
	s.thread.Reset()
	s.user.Reset()
	s.ancestor.Reset()
	s.executable.Reset()
	s.container.Reset()
	s.containerImage.Reset()
	s.k8s.Reset()
	s.k8sNamespace.Reset()
	s.pod.Reset()
	s.policies.Reset()
	s.userStackTrace.Reset()

	for i := range s.uint32s {
		s.uint32s[i].Value = 0
	}
	for i := range s.timestamps {
		s.timestamps[i].Seconds = 0
		s.timestamps[i].Nanos = 0
	}
	for i := range s.dataValues {
		s.dataValues[i].Reset()
		s.dataPtrs[i] = nil
	}
}

var protoSlabPool = sync.Pool{
	New: func() interface{} { return new(eventSlab) },
}
