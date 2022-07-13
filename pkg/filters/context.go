package filters

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type ContextFilter struct {
	filters map[events.ID]*eventCtxFilter
	enabled bool
}

func NewContextFilter() *ContextFilter {
	return &ContextFilter{
		filters: make(map[events.ID]*eventCtxFilter),
		enabled: false,
	}
}

func (filter *ContextFilter) Enable() {
	filter.enabled = true
	for _, f := range filter.filters {
		f.Enable()
	}
}

func (filter *ContextFilter) Disable() {
	filter.enabled = false
	for _, f := range filter.filters {
		f.Disable()
	}
}

func (filter *ContextFilter) Enabled() bool {
	return filter.enabled
}

func (filter *ContextFilter) Filter(event trace.Event) bool {
	if !filter.enabled {
		return true
	}

	if filter, ok := filter.filters[events.ID(event.EventID)]; ok {
		if !filter.Filter(event) {
			return false
		}
	}
	return true
}

func (filter *ContextFilter) Add(filterReq protocol.Filter) error {
	field := filterReq.Field
	parts := strings.Split(field, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid context filter format: %s", field)
	}
	if parts[1] != "context" {
		return fmt.Errorf("invalid context filter format: %s", field)
	}

	eventName := parts[0]
	eventField := parts[2]

	id, ok := events.Definitions.GetID(eventName)
	if !ok {
		return fmt.Errorf("invalid context filter event name: %s", eventName)
	}
	eventFilter := filter.filters[id]
	if eventFilter == nil {
		eventFilter = &eventCtxFilter{
			enabled:              filter.enabled,
			timestampFilter:      NewIntFilter(),
			processorIDFilter:    NewIntFilter(),
			pidFilter:            NewIntFilter(),
			tidFilter:            NewIntFilter(),
			ppidFilter:           NewIntFilter(),
			hostPidFilter:        NewIntFilter(),
			hostTidFilter:        NewIntFilter(),
			hostPpidFilter:       NewIntFilter(),
			uidFilter:            NewIntFilter(),
			mntNSFilter:          NewIntFilter(),
			pidNSFilter:          NewIntFilter(),
			processNameFilter:    NewStringFilter(),
			hostNameFilter:       NewStringFilter(),
			cgroupIDFilter:       NewUIntFilter(),
			containerFilter:      NewBoolFilter(),
			containerIDFilter:    NewStringFilter(),
			containerImageFilter: NewStringFilter(),
			containerNameFilter:  NewStringFilter(),
			podNameFilter:        NewStringFilter(),
			podNSFilter:          NewStringFilter(),
			podUIDFilter:         NewStringFilter(),
		}
		filter.filters[id] = eventFilter
	}

	err := eventFilter.Add(protocol.Filter{Field: eventField, Operator: filterReq.Operator, Value: filterReq.Value})
	if err != nil {
		return fmt.Errorf("failed to set context filter: %s", err)
	}
	return nil
}

type eventCtxFilter struct {
	enabled              bool
	timestampFilter      *IntFilter
	processorIDFilter    *IntFilter
	pidFilter            *IntFilter
	tidFilter            *IntFilter
	ppidFilter           *IntFilter
	hostPidFilter        *IntFilter
	hostTidFilter        *IntFilter
	hostPpidFilter       *IntFilter
	uidFilter            *IntFilter
	mntNSFilter          *IntFilter
	pidNSFilter          *IntFilter
	processNameFilter    *StringFilter
	hostNameFilter       *StringFilter
	cgroupIDFilter       *UIntFilter
	containerFilter      *BoolFilter
	containerIDFilter    *StringFilter
	containerImageFilter *StringFilter
	containerNameFilter  *StringFilter
	podNameFilter        *StringFilter
	podNSFilter          *StringFilter
	podUIDFilter         *StringFilter
}

func (f *eventCtxFilter) Enable() {
	f.enabled = true
}

func (f *eventCtxFilter) Disable() {
	f.enabled = false
}

func (filter *eventCtxFilter) Filter(evt trace.Event) bool {
	if !filter.enabled {
		return true
	}

	// TODO: optimize the order of filter calls
	// if we order this by most to least likely filter to be set
	// we can short circuit this logic.
	return filter.containerFilter.Filter(evt.ContainerID != "") &&
		filter.processNameFilter.Filter(evt.ProcessName) &&
		filter.timestampFilter.Filter(int64(evt.Timestamp)) &&
		filter.cgroupIDFilter.Filter(uint64(evt.CgroupID)) &&
		filter.containerIDFilter.Filter(evt.ContainerID) &&
		filter.containerImageFilter.Filter(evt.ContainerImage) &&
		filter.containerNameFilter.Filter(evt.ContainerName) &&
		filter.hostNameFilter.Filter(evt.HostName) &&
		filter.hostPidFilter.Filter(int64(evt.HostProcessID)) &&
		filter.hostPpidFilter.Filter(int64(evt.HostParentProcessID)) &&
		filter.hostTidFilter.Filter(int64(evt.HostThreadID)) &&
		filter.mntNSFilter.Filter(int64(evt.MountNS)) &&
		filter.pidFilter.Filter(int64(evt.ProcessID)) &&
		filter.ppidFilter.Filter(int64(evt.ParentProcessID)) &&
		filter.pidNSFilter.Filter(int64(evt.PIDNS)) &&
		filter.processorIDFilter.Filter(int64(evt.ProcessorID)) &&
		filter.podNameFilter.Filter(evt.ContainerImage) &&
		filter.podNSFilter.Filter(evt.PodNamespace) &&
		filter.podUIDFilter.Filter(evt.PodUID) &&
		filter.tidFilter.Filter(int64(evt.ThreadID)) &&
		filter.uidFilter.Filter(int64(evt.UserID))
}

func (f *eventCtxFilter) Add(req protocol.Filter) error {
	switch req.Field {
	case "timestamp":
		filter := f.timestampFilter
		return f.add(filter, req)
	case "processorId":
		filter := f.processorIDFilter
		return f.add(filter, req)
	case "p", "pid", "processId":
		filter := f.pidFilter
		return f.add(filter, req)
	case "tid", "threadId":
		filter := f.tidFilter
		return f.add(filter, req)
	case "ppid", "parentProcessId":
		filter := f.ppidFilter
		return f.add(filter, req)
	case "hostTid", "hostThreadId":
		filter := f.hostTidFilter
		return f.add(filter, req)
	case "hostPid", "hostParentProcessId":
		filter := f.hostPidFilter
		return f.add(filter, req)
	case "uid", "userId":
		filter := f.uidFilter
		return f.add(filter, req)
	case "mntns", "mountNamespace":
		filter := f.mntNSFilter
		return f.add(filter, req)
	case "pidns", "pidNamespace":
		filter := f.pidNSFilter
		return f.add(filter, req)
	case "processName", "comm":
		filter := f.processNameFilter
		return f.add(filter, req)
	case "hostName":
		filter := f.hostNameFilter
		return f.add(filter, req)
	case "cgroupId":
		filter := f.cgroupIDFilter
		return f.add(filter, req)
	// we reserve host for negating "container" context requests
	case "host":
		filter := f.containerFilter
		return f.add(filter, req.Not())
	case "containerId":
		filter := f.containerIDFilter
		return f.addContainer(filter, req)
	case "containerImage":
		filter := f.containerImageFilter
		return f.addContainer(filter, req)
	case "containerName":
		filter := f.containerNameFilter
		return f.addContainer(filter, req)
	case "podName":
		filter := f.podNameFilter
		return f.addContainer(filter, req)
	case "podNamespace":
		filter := f.podNSFilter
		return f.addContainer(filter, req)
	case "podUid":
		filter := f.podUIDFilter
		return f.addContainer(filter, req)
	}
	return nil
}

func (f *eventCtxFilter) add(filter Filter, req protocol.Filter) error {
	err := filter.Add(req)
	if err != nil {
		return err
	}
	filter.Enable()
	return nil
}

func (f *eventCtxFilter) addContainer(filter Filter, req protocol.Filter) error {
	err := f.add(filter, req)
	if err != nil {
		return err
	}
	f.containerFilter.add(true, Equal)
	f.containerFilter.Enable()
	return nil
}
