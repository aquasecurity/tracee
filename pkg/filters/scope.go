package filters

import (
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/interfaces"
	"github.com/aquasecurity/tracee/types/trace"
)

// ScopeName represents a scope dimension name for filtering
type ScopeName string

// Scope name constants for filtering
const (
	// Boolean scope filters
	ScopeContainer ScopeName = "container" // Matches container contexts
	ScopeHost      ScopeName = "host"      // Matches host (non-container) contexts

	// Process ID scope filters
	ScopePID                 ScopeName = "pid"                 // Process ID
	ScopeProcessID           ScopeName = "processId"           // Alias for pid
	ScopeP                   ScopeName = "p"                   // Short alias for pid
	ScopeTID                 ScopeName = "tid"                 // Thread ID
	ScopeThreadID            ScopeName = "threadId"            // Alias for tid
	ScopePPID                ScopeName = "ppid"                // Parent process ID
	ScopeParentProcID        ScopeName = "parentProcessId"     // Alias for ppid
	ScopeHostPID             ScopeName = "hostPid"             // Host process ID
	ScopeHostTID             ScopeName = "hostTid"             // Host thread ID
	ScopeHostThreadID        ScopeName = "hostThreadId"        // Alias for hostTid
	ScopeHostPPID            ScopeName = "hostPpid"            // Host parent process ID
	ScopeHostParentProcessID ScopeName = "hostParentProcessId" // Alias for hostPid

	// User scope filters
	ScopeUID    ScopeName = "uid"    // User ID
	ScopeUserID ScopeName = "userId" // Alias for uid

	// Namespace scope filters
	ScopeMntNS          ScopeName = "mntns"          // Mount namespace
	ScopeMountNamespace ScopeName = "mountNamespace" // Alias for mntns
	ScopePidNS          ScopeName = "pidns"          // PID namespace
	ScopePidNamespace   ScopeName = "pidNamespace"   // Alias for pidns

	// Process name scope filters
	ScopeComm        ScopeName = "comm"        // Process command name
	ScopeProcessName ScopeName = "processName" // Alias for comm

	// Host scope filter
	ScopeHostName ScopeName = "hostName" // Hostname

	// Cgroup scope filter
	ScopeCgroupID ScopeName = "cgroupId" // Cgroup ID

	// Container attribute scope filters
	ScopeContainerID          ScopeName = "containerId"          // Container ID
	ScopeContainerImage       ScopeName = "containerImage"       // Container image name
	ScopeContainerName        ScopeName = "containerName"        // Container name
	ScopeContainerImageDigest ScopeName = "containerImageDigest" // Container image digest

	// Kubernetes pod scope filters
	ScopePodName      ScopeName = "podName"      // Kubernetes pod name
	ScopePodNamespace ScopeName = "podNamespace" // Kubernetes pod namespace
	ScopePodNs        ScopeName = "podNs"        // Short alias for podNamespace
	ScopePodUID       ScopeName = "podUid"       // Kubernetes pod UID
	ScopePodSandbox   ScopeName = "podSandbox"   // Kubernetes pod sandbox

	// Other scope filters
	ScopeSyscall     ScopeName = "syscall"     // Syscall filtering
	ScopeTimestamp   ScopeName = "timestamp"   // Timestamp filtering
	ScopeProcessorID ScopeName = "processorId" // Processor ID filtering
)

type ScopeFilter struct {
	enabled                    bool
	timestampFilter            *NumericFilter[int64]
	processorIDFilter          *NumericFilter[int64]
	pidFilter                  *NumericFilter[int64]
	tidFilter                  *NumericFilter[int64]
	ppidFilter                 *NumericFilter[int64]
	hostPidFilter              *NumericFilter[int64]
	hostTidFilter              *NumericFilter[int64]
	hostPpidFilter             *NumericFilter[int64]
	uidFilter                  *NumericFilter[int64]
	mntNSFilter                *NumericFilter[int64]
	pidNSFilter                *NumericFilter[int64]
	processNameFilter          *StringFilter
	hostNameFilter             *StringFilter
	cgroupIDFilter             *NumericFilter[uint64]
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

// Compile-time check to ensure that ScopeFilter implements the Cloner interface
var _ interfaces.Cloner[*ScopeFilter] = &ScopeFilter{}

func NewScopeFilter() *ScopeFilter {
	return &ScopeFilter{
		enabled:                    false,
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
}

func (f *ScopeFilter) Enable() {
	f.enabled = true
}

func (f *ScopeFilter) Disable() {
	f.enabled = false
}

func (f *ScopeFilter) Enabled() bool {
	return f.enabled
}

func (f *ScopeFilter) Filter(evt trace.Event) bool {
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

func (f *ScopeFilter) Parse(field ScopeName, operatorAndValues string) error {
	f.Enable()

	switch field {
	case ScopeTimestamp:
		filter := f.timestampFilter
		return filter.Parse(operatorAndValues)
	case ScopeProcessorID:
		filter := f.processorIDFilter
		return filter.Parse(operatorAndValues)
	case ScopeP, ScopePID, ScopeProcessID:
		filter := f.pidFilter
		return filter.Parse(operatorAndValues)
	case ScopeTID, ScopeThreadID:
		filter := f.tidFilter
		return filter.Parse(operatorAndValues)
	case ScopePPID, ScopeParentProcID:
		filter := f.ppidFilter
		return filter.Parse(operatorAndValues)
	case ScopeHostTID, ScopeHostThreadID:
		filter := f.hostTidFilter
		return filter.Parse(operatorAndValues)
	case ScopeHostPID, ScopeHostParentProcessID:
		filter := f.hostPidFilter
		return filter.Parse(operatorAndValues)
	case ScopeHostPPID:
		filter := f.hostPpidFilter
		return filter.Parse(operatorAndValues)
	case ScopeUID, ScopeUserID:
		filter := f.uidFilter
		return filter.Parse(operatorAndValues)
	case ScopeMntNS, ScopeMountNamespace:
		filter := f.mntNSFilter
		return filter.Parse(operatorAndValues)
	case ScopePidNS, ScopePidNamespace:
		filter := f.pidNSFilter
		return filter.Parse(operatorAndValues)
	case ScopeProcessName, ScopeComm:
		filter := f.processNameFilter
		return filter.Parse(operatorAndValues)
	case ScopeHostName:
		filter := f.hostNameFilter
		return filter.Parse(operatorAndValues)
	case ScopeCgroupID:
		filter := f.cgroupIDFilter
		return filter.Parse(operatorAndValues)
	// we reserve host for negating "container" scope
	case ScopeHost:
		filter := f.containerFilter
		filter.Enable()
		return filter.add(false, Equal)
	case ScopeContainer:
		filter := f.containerFilter
		filter.Enable()
		return filter.add(true, Equal)
	// TODO: change this and below container filters to the format
	// eventname.scope.container.id and so on...
	case ScopeContainerID:
		filter := f.containerIDFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopeContainerImage:
		filter := f.containerImageFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopeContainerImageDigest:
		filter := f.containerImageDigestFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopeContainerName:
		filter := f.containerNameFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	// TODO: change this and below pod filters to the format
	// eventname.scope.kubernetes.podName and so on...
	case ScopePodName:
		filter := f.podNameFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopePodNamespace, ScopePodNs:
		filter := f.podNSFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopePodUID:
		filter := f.podUIDFilter
		return addContainer[*StringFilter](f, filter, operatorAndValues)
	case ScopePodSandbox:
		filter := f.podSandboxFilter
		return addContainer[*BoolFilter](f, filter, operatorAndValues)
	case ScopeSyscall:
		filter := f.syscallFilter
		return filter.Parse(operatorAndValues)
	}
	return InvalidScopeField(field)
}

func addContainer[T any](f *ScopeFilter, filter Filter[T], operatorAndValues string) error {
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

// HasScopeFiltering returns true if the specified scope dimension has active filtering.
// Returns false for unknown scope names.
func (f *ScopeFilter) HasScopeFiltering(scope ScopeName) bool {
	if f == nil {
		return false
	}

	if !f.enabled {
		return false
	}

	switch scope {
	case ScopeContainer:
		return f.containerFilter.Enabled() && f.containerFilter.IsTrueEnabled()
	case ScopeHost:
		return f.containerFilter.Enabled() && f.containerFilter.IsFalseEnabled()
	case ScopePID, ScopeP, ScopeProcessID:
		return f.pidFilter.Enabled()
	case ScopeTID, ScopeThreadID:
		return f.tidFilter.Enabled()
	case ScopePPID, ScopeParentProcID:
		return f.ppidFilter.Enabled()
	case ScopeHostPID, ScopeHostParentProcessID:
		return f.hostPidFilter.Enabled()
	case ScopeHostTID, ScopeHostThreadID:
		return f.hostTidFilter.Enabled()
	case ScopeHostPPID:
		return f.hostPpidFilter.Enabled()
	case ScopeUID, ScopeUserID:
		return f.uidFilter.Enabled()
	case ScopeMntNS, ScopeMountNamespace:
		return f.mntNSFilter.Enabled()
	case ScopePidNS, ScopePidNamespace:
		return f.pidNSFilter.Enabled()
	case ScopeComm, ScopeProcessName:
		return f.processNameFilter.Enabled()
	case ScopeHostName:
		return f.hostNameFilter.Enabled()
	case ScopeCgroupID:
		return f.cgroupIDFilter.Enabled()
	case ScopeContainerID:
		return f.containerIDFilter.Enabled()
	case ScopeContainerImage:
		return f.containerImageFilter.Enabled()
	case ScopeContainerName:
		return f.containerNameFilter.Enabled()
	case ScopeContainerImageDigest:
		return f.containerImageDigestFilter.Enabled()
	case ScopePodName:
		return f.podNameFilter.Enabled()
	case ScopePodNamespace, ScopePodNs:
		return f.podNSFilter.Enabled()
	case ScopePodUID:
		return f.podUIDFilter.Enabled()
	case ScopePodSandbox:
		return f.podSandboxFilter.Enabled()
	case ScopeSyscall:
		return f.syscallFilter.Enabled()
	case ScopeTimestamp:
		return f.timestampFilter.Enabled()
	case ScopeProcessorID:
		return f.processorIDFilter.Enabled()
	default:
		return false
	}
}

func (f *ScopeFilter) Clone() *ScopeFilter {
	if f == nil {
		return nil
	}

	n := &ScopeFilter{}

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
