package filters

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

type ScopeFilter struct {
	filters map[events.ID]*eventCtxFilter
	enabled bool
}

// Compile-time check to ensure that ScopeFilter implements the Cloner interface
var _ utils.Cloner[*ScopeFilter] = &ScopeFilter{}

func NewScopeFilter() *ScopeFilter {
	return &ScopeFilter{
		filters: make(map[events.ID]*eventCtxFilter),
		enabled: false,
	}
}

func (filter *ScopeFilter) Enable() {
	filter.enabled = true
	for _, f := range filter.filters {
		f.Enable()
	}
}

func (filter *ScopeFilter) Disable() {
	filter.enabled = false
	for _, f := range filter.filters {
		f.Disable()
	}
}

func (filter *ScopeFilter) Enabled() bool {
	return filter.enabled
}

func (filter *ScopeFilter) Filter(event trace.Event) bool {
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

func (filter *ScopeFilter) Parse(filterName string, operatorAndValues string) error {
	parts := strings.Split(filterName, ".")
	if len(parts) != 3 {
		return InvalidExpression(filterName + operatorAndValues)
	}
	if parts[1] != "scope" {
		return InvalidExpression(filterName + operatorAndValues)
	}

	eventName := parts[0]
	eventField := parts[2]

	eventDefID, ok := events.Core.GetDefinitionIDByName(eventName)
	if !ok {
		return InvalidEventName(eventName)
	}

	eventFilter := filter.filters[eventDefID]
	if eventFilter == nil {
		eventFilter = &eventCtxFilter{
			enabled:                    filter.enabled,
			timestampFilter:            NewIntFilter(),
			processorIDFilter:          NewIntFilter(),
			pidFilter:                  NewIntFilter(),
			tidFilter:                  NewIntFilter(),
			ppidFilter:                 NewIntFilter(),
			hostPidFilter:              NewIntFilter(),
			hostTidFilter:              NewIntFilter(),
			hostPpidFilter:             NewIntFilter(),
			uidFilter:                  NewIntFilter(),
			mntNSFilter:                NewIntFilter(),
			pidNSFilter:                NewIntFilter(),
			processNameFilter:          NewStringFilter(nil),
			hostNameFilter:             NewStringFilter(nil),
			cgroupIDFilter:             NewUIntFilter(),
			containerFilter:            NewBoolFilter(),
			containerIDFilter:          NewStringFilter(nil),
			containerImageFilter:       NewStringFilter(nil),
			containerImageDigestFilter: NewStringFilter(nil),
			containerNameFilter:        NewStringFilter(nil),
			podNameFilter:              NewStringFilter(nil),
			podNSFilter:                NewStringFilter(nil),
			podUIDFilter:               NewStringFilter(nil),
			podSandboxFilter:           NewBoolFilter(),
			syscallFilter:              NewStringFilter(nil),
		}
		filter.filters[eventDefID] = eventFilter
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

// Compile-time check to ensure that eventCtxFilter implements the Cloner interface
var _ utils.Cloner[*eventCtxFilter] = &eventCtxFilter{}

func (f *eventCtxFilter) Enable() {
	f.enabled = true
}

func (f *eventCtxFilter) Disable() {
	f.enabled = false
}

func (f *eventCtxFilter) Filter(evt trace.Event) bool {
	if !f.enabled {
		return true
	}

	// TODO: optimize the order of filter calls
	// if we order this by most to least likely filter to be set
	// we can short circuit this logic.
	return f.containerFilter.Filter(evt.Container.ID != "") &&
		f.processNameFilter.Filter(evt.ProcessName) &&
		f.timestampFilter.Filter(int64(evt.Timestamp)) &&
		f.cgroupIDFilter.Filter(uint64(evt.CgroupID)) &&
		f.containerIDFilter.Filter(evt.Container.ID) &&
		f.containerImageFilter.Filter(evt.Container.ImageName) &&
		f.containerNameFilter.Filter(evt.Container.Name) &&
		f.hostNameFilter.Filter(evt.HostName) &&
		f.hostPidFilter.Filter(int64(evt.HostProcessID)) &&
		f.hostPpidFilter.Filter(int64(evt.HostParentProcessID)) &&
		f.syscallFilter.Filter(evt.Syscall) &&
		f.hostTidFilter.Filter(int64(evt.HostThreadID)) &&
		f.mntNSFilter.Filter(int64(evt.MountNS)) &&
		f.pidFilter.Filter(int64(evt.ProcessID)) &&
		f.ppidFilter.Filter(int64(evt.ParentProcessID)) &&
		f.pidNSFilter.Filter(int64(evt.PIDNS)) &&
		f.processorIDFilter.Filter(int64(evt.ProcessorID)) &&
		f.podNameFilter.Filter(evt.Kubernetes.PodName) &&
		f.podNSFilter.Filter(evt.Kubernetes.PodNamespace) &&
		f.podUIDFilter.Filter(evt.Kubernetes.PodUID) &&
		f.tidFilter.Filter(int64(evt.ThreadID)) &&
		f.uidFilter.Filter(int64(evt.UserID))
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
	// we reserve host for negating "container" scope
	case "host":
		filter := f.containerFilter
		filter.Enable()
		return filter.add(false, Equal)
	case "container":
		filter := f.containerFilter
		filter.Enable()
		return filter.add(true, Equal)
	// TODO: change this and below container filters to the format
	// eventname.scope.container.id and so on...
	case "containerId":
		filter := f.containerIDFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "containerImage":
		filter := f.containerImageFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "containerImageDigest":
		filter := f.containerImageDigestFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "containerName":
		filter := f.containerNameFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	// TODO: change this and below pod filters to the format
	// eventname.scope.kubernetes.podName and so on...
	case "podName":
		filter := f.podNameFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "podNamespace":
		filter := f.podNSFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "podUid":
		filter := f.podUIDFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case "podSandbox":
		filter := f.podSandboxFilter
		return addContainer[*BoolFilter](f, filter, operatorAndValues)
	case "syscall":
		filter := f.syscallFilter
		return filter.Parse(operatorAndValues)
	}
	return InvalidScopeField(field)
}

func addContainer[T any](f *eventCtxFilter, filter Filter[T], operatorAndValues string) error {
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

func (f *eventCtxFilter) Clone() *eventCtxFilter {
	if f == nil {
		return nil
	}

	n := &eventCtxFilter{}

	n.enabled = f.enabled
	n.timestampFilter = f.timestampFilter.Clone()
	n.processorIDFilter = f.processorIDFilter.Clone()
	n.pidFilter = f.pidFilter.Clone()
	n.tidFilter = f.tidFilter.Clone()
	n.ppidFilter = f.ppidFilter.Clone()
	n.hostPidFilter = f.hostPidFilter.Clone()
	n.hostTidFilter = f.hostTidFilter.Clone()
	n.hostPpidFilter = f.hostPpidFilter.Clone()
	n.uidFilter = f.uidFilter.Clone()
	n.mntNSFilter = f.mntNSFilter.Clone()
	n.pidNSFilter = f.pidNSFilter.Clone()
	n.processNameFilter = f.processNameFilter.Clone()
	n.hostNameFilter = f.hostNameFilter.Clone()
	n.cgroupIDFilter = f.cgroupIDFilter.Clone()
	n.containerFilter = f.containerFilter.Clone()
	n.containerIDFilter = f.containerIDFilter.Clone()
	n.containerImageFilter = f.containerImageFilter.Clone()
	n.containerImageDigestFilter = f.containerImageDigestFilter.Clone()
	n.containerNameFilter = f.containerNameFilter.Clone()
	n.podNameFilter = f.podNameFilter.Clone()
	n.podNSFilter = f.podNSFilter.Clone()
	n.podUIDFilter = f.podUIDFilter.Clone()
	n.podSandboxFilter = f.podSandboxFilter.Clone()
	n.syscallFilter = f.syscallFilter.Clone()

	return n
}

func (filter *ScopeFilter) Clone() *ScopeFilter {
	if filter == nil {
		return nil
	}

	n := NewScopeFilter()

	for k, v := range filter.filters {
		n.filters[k] = v.Clone()
	}

	n.enabled = filter.enabled

	return n
}
