package detectors

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
)

// EventOption is a functional option for building events
type EventOption func(*v1beta1.Event)

// NewExecveEvent creates an execve event for testing
func NewExecveEvent(pathname string, opts ...EventOption) *v1beta1.Event {
	event := &v1beta1.Event{
		Id:        v1beta1.EventId(events.Execve),
		Name:      "execve",
		Timestamp: timestamppb.Now(),
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", pathname),
		},
	}

	for _, opt := range opts {
		opt(event)
	}

	return event
}

// NewSchedProcessExecEvent creates a sched_process_exec event for testing
func NewSchedProcessExecEvent(pathname string, opts ...EventOption) *v1beta1.Event {
	event := &v1beta1.Event{
		Id:        v1beta1.EventId(events.SchedProcessExec),
		Name:      "sched_process_exec",
		Timestamp: timestamppb.Now(),
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", pathname),
		},
	}

	for _, opt := range opts {
		opt(event)
	}

	return event
}

// NewOpenatEvent creates an openat event for testing
func NewOpenatEvent(pathname string, flags string, opts ...EventOption) *v1beta1.Event {
	event := &v1beta1.Event{
		Id:        v1beta1.EventId(events.Openat),
		Name:      "openat",
		Timestamp: timestamppb.Now(),
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", pathname),
			v1beta1.NewStringValue("flags", flags),
		},
	}

	for _, opt := range opts {
		opt(event)
	}

	return event
}

// NewNetworkEvent creates a generic network event for testing
func NewNetworkEvent(srcIP, dstIP string, opts ...EventOption) *v1beta1.Event {
	event := &v1beta1.Event{
		Id:        v1beta1.EventId(events.NetPacketIPv4),
		Name:      "net_packet_ipv4",
		Timestamp: timestamppb.Now(),
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("src", srcIP),
			v1beta1.NewStringValue("dst", dstIP),
		},
	}

	for _, opt := range opts {
		opt(event)
	}

	return event
}

// WithWorkloadProcess adds process information to an event
func WithWorkloadProcess(pid uint32, comm string) EventOption {
	return func(event *v1beta1.Event) {
		if event.Workload == nil {
			event.Workload = &v1beta1.Workload{}
		}
		if event.Workload.Process == nil {
			event.Workload.Process = &v1beta1.Process{}
		}

		event.Workload.Process.Pid = &wrapperspb.UInt32Value{Value: pid}
		event.Workload.Process.HostPid = &wrapperspb.UInt32Value{Value: pid}
		event.Workload.Process.UniqueId = &wrapperspb.UInt32Value{Value: pid}

		if comm != "" {
			if event.Workload.Process.Thread == nil {
				event.Workload.Process.Thread = &v1beta1.Thread{}
			}
			event.Workload.Process.Thread.Name = comm
		}
	}
}

// WithContainer adds container information to an event
func WithContainer(id, name string) EventOption {
	return func(event *v1beta1.Event) {
		if event.Workload == nil {
			event.Workload = &v1beta1.Workload{}
		}
		if event.Workload.Container == nil {
			event.Workload.Container = &v1beta1.Container{}
		}

		event.Workload.Container.Id = id
		event.Workload.Container.Name = name
		event.Workload.Container.Started = true
	}
}

// WithK8s adds Kubernetes information to an event
func WithK8s(podName, namespace string) EventOption {
	return func(event *v1beta1.Event) {
		if event.Workload == nil {
			event.Workload = &v1beta1.Workload{}
		}
		if event.Workload.K8S == nil {
			event.Workload.K8S = &v1beta1.K8S{}
		}

		if event.Workload.K8S.Pod == nil {
			event.Workload.K8S.Pod = &v1beta1.Pod{}
		}

		event.Workload.K8S.Pod.Name = podName

		if event.Workload.K8S.Namespace == nil {
			event.Workload.K8S.Namespace = &v1beta1.K8SNamespace{}
		}

		event.Workload.K8S.Namespace.Name = namespace
	}
}

// WithTimestamp sets a custom timestamp on an event
func WithTimestamp(ts time.Time) EventOption {
	return func(event *v1beta1.Event) {
		event.Timestamp = timestamppb.New(ts)
	}
}

// WithData adds custom data fields to an event
func WithData(values ...*v1beta1.EventValue) EventOption {
	return func(event *v1beta1.Event) {
		event.Data = append(event.Data, values...)
	}
}

// WithEventID sets a custom event ID
func WithEventID(id events.ID) EventOption {
	return func(event *v1beta1.Event) {
		event.Id = v1beta1.EventId(id)
	}
}

// WithEventName sets a custom event name
func WithEventName(name string) EventOption {
	return func(event *v1beta1.Event) {
		event.Name = name
	}
}
