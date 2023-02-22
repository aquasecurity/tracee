package filters

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
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
	if !filter.Enabled() {
		return true
	}

	if filter, ok := filter.filters[events.ID(event.EventID)]; ok {
		if !filter.Filter(event) {
			return false
		}
	}
	return true
}

func (filter *ContextFilter) Parse(filterName string, operatorAndValues string) error {
	parts := strings.Split(filterName, ".")
	if len(parts) != 3 {
		return InvalidExpression(filterName + operatorAndValues)

	}
	if parts[1] != "context" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := parts[0]
	eventField := parts[2]

	id, ok := events.Definitions.GetID(eventName)
	if !ok {
		return InvalidEventName(eventName)
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
			podSandboxFilter:     NewBoolFilter(),
			syscallFilter:        NewStringFilter(),
		}
		filter.filters[id] = eventFilter
	}

	err := eventFilter.Parse(eventField, operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}

	filter.Enable()
	return nil
}

type eventCtxFilter struct {
	enabled                    bool
	timestampFilter            *IntFilter[int64]
	processorIDFilter          *IntFilter[int64]
	pidFilter                  *IntFilter[int64]
	tidFilter                  *IntFilter[int64]
	ppidFilter                 *IntFilter[int64]
	hostPidFilter              *IntFilter[int64]
	hostTidFilter              *IntFilter[int64]
	hostPpidFilter             *IntFilter[int64]
	uidFilter                  *IntFilter[int64]
	mntNSFilter                *IntFilter[int64]
	pidNSFilter                *IntFilter[int64]
	processNameFilter          *StringFilter
	hostNameFilter             *StringFilter
	cgroupIDFilter             *UIntFilter[uint64]
	containerFilter            *BoolFilter
	containerIDFilter          *StringFilter
	containerImageFilter       *StringFilter
	containerImageDigestFilter *StringFilter
	containerNameFilter        *StringFilter
	podNameFilter              *StringFilter
	podNSFilter                *StringFilter
	podUIDFilter               *StringFilter
	podSandboxFilter           *BoolFilter
	syscallFilter              *StringFilter
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
	return filter.containerFilter.Filter(evt.Container.ID != "") &&
		filter.processNameFilter.Filter(evt.ProcessName) &&
		filter.timestampFilter.Filter(int64(evt.Timestamp)) &&
		filter.cgroupIDFilter.Filter(uint64(evt.CgroupID)) &&
		filter.containerIDFilter.Filter(evt.Container.ID) &&
		filter.containerImageFilter.Filter(evt.Container.ImageName) &&
		filter.containerNameFilter.Filter(evt.Container.Name) &&
		filter.hostNameFilter.Filter(evt.HostName) &&
		filter.hostPidFilter.Filter(int64(evt.HostProcessID)) &&
		filter.hostPpidFilter.Filter(int64(evt.HostParentProcessID)) &&
		filter.syscallFilter.Filter(evt.Syscall) &&
		filter.hostTidFilter.Filter(int64(evt.HostThreadID)) &&
		filter.mntNSFilter.Filter(int64(evt.MountNS)) &&
		filter.pidFilter.Filter(int64(evt.ProcessID)) &&
		filter.ppidFilter.Filter(int64(evt.ParentProcessID)) &&
		filter.pidNSFilter.Filter(int64(evt.PIDNS)) &&
		filter.processorIDFilter.Filter(int64(evt.ProcessorID)) &&
		filter.podNameFilter.Filter(evt.Kubernetes.PodName) &&
		filter.podNSFilter.Filter(evt.Kubernetes.PodNamespace) &&
		filter.podUIDFilter.Filter(evt.Kubernetes.PodUID) &&
		filter.tidFilter.Filter(int64(evt.ThreadID)) &&
		filter.uidFilter.Filter(int64(evt.UserID))
}

func (f *eventCtxFilter) Parse(field string, operatorAndValues string) error {
	f.Enable()

	switch field {
	case "timestamp":
		filter := f.timestampFilter
		return filter.Parse(operatorAndValues)
	case "processorId":
		filter := f.processorIDFilter
		return filter.Parse(operatorAndValues)
	case "p", "pid", "processId":
		filter := f.pidFilter
		return filter.Parse(operatorAndValues)
	case "tid", "threadId":
		filter := f.tidFilter
		return filter.Parse(operatorAndValues)
	case "ppid", "parentProcessId":
		filter := f.ppidFilter
		return filter.Parse(operatorAndValues)
	case "hostTid", "hostThreadId":
		filter := f.hostTidFilter
		return filter.Parse(operatorAndValues)
	case "hostPid", "hostParentProcessId":
		filter := f.hostPidFilter
		return filter.Parse(operatorAndValues)
	case "uid", "userId":
		filter := f.uidFilter
		return filter.Parse(operatorAndValues)
	case "mntns", "mountNamespace":
		filter := f.mntNSFilter
		return filter.Parse(operatorAndValues)
	case "pidns", "pidNamespace":
		filter := f.pidNSFilter
		return filter.Parse(operatorAndValues)
	case "processName", "comm":
		filter := f.processNameFilter
		return filter.Parse(operatorAndValues)
	case "hostName":
		filter := f.hostNameFilter
		return filter.Parse(operatorAndValues)
	case "cgroupId":
		filter := f.cgroupIDFilter
		return filter.Parse(operatorAndValues)
	// we reserve host for negating "container" context
	case "host":
		filter := f.containerFilter
		filter.Enable()
		return filter.add(false, Equal)
	case "container":
		filter := f.containerFilter
		filter.Enable()
		return filter.add(true, Equal)
	// TODO: change this and below container filters to the format
	// eventname.context.container.id and so on...
	case "containerId":
		filter := f.containerIDFilter
		return f.addContainer(filter, operatorAndValues)
	case "containerImage":
		filter := f.containerImageFilter
		return f.addContainer(filter, operatorAndValues)
	case "containerImageDigest":
		filter := f.containerImageDigestFilter
		return f.addContainer(filter, operatorAndValues)
	case "containerName":
		filter := f.containerNameFilter
		return f.addContainer(filter, operatorAndValues)
	// TODO: change this and below pod filters to the format
	// eventname.context.kubernetes.podName and so on...
	case "podName":
		filter := f.podNameFilter
		return f.addContainer(filter, operatorAndValues)
	case "podNamespace":
		filter := f.podNSFilter
		return f.addContainer(filter, operatorAndValues)
	case "podUid":
		filter := f.podUIDFilter
		return f.addContainer(filter, operatorAndValues)
	case "podSandbox":
		filter := f.podSandboxFilter
		return f.addContainer(filter, operatorAndValues)
	case "syscall":
		filter := f.syscallFilter
		return filter.Parse(operatorAndValues)
	}
	return InvalidContextField(field)
}

func (f *eventCtxFilter) addContainer(filter Filter, operatorAndValues string) error {
	err := filter.Parse(operatorAndValues)
	if err != nil {
		return errfmt.WrapError(err)
	}
	if err = f.containerFilter.add(true, Equal); err != nil {
		return errfmt.WrapError(err)
	}
	f.containerFilter.Enable()
	return nil
}
