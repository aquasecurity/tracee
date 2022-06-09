package main

import (
	"github.com/aquasecurity/tracee/pkg/capabilities"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// IKernelVersionInfo is an interface to check kernel version
type IKernelVersionInfo interface {
	// CompareOSBaseKernelRelease compare given kernel version to current one.
	// The return value is -1, 0 or 1 if given version is less,
	// equal or bigger, respectively, than running one.
	CompareOSBaseKernelRelease(string) int
}

// ensureCapabilities makes sure program runs with required capabilities only
func ensureCapabilities(OSInfo IKernelVersionInfo, cfg *tracee.Config) error {
	selfCap, err := capabilities.Self()
	if err != nil {
		return err
	}

	rCaps, err := generateTraceeEbpfRequiredCapabilities(OSInfo, cfg, selfCap)
	if err != nil {
		return err
	}

	if err = capabilities.CheckRequired(selfCap, rCaps); err != nil {
		return err
	}
	if err = capabilities.DropUnrequired(selfCap, rCaps); err != nil {
		return err
	}

	return nil
}

// Get all capabilities required to run tracee-ebpf for current run
func generateTraceeEbpfRequiredCapabilities(OSInfo IKernelVersionInfo, cfg *tracee.Config, selfCap capabilities.ICapabilitiesSet) (
	[]cap.Value, error) {
	rCaps, err := getCapabilitiesRequiredByEBPF(selfCap, OSInfo)
	if err != nil {
		return nil, err
	}
	rCaps = append(rCaps, getCapabilitiesRequiredByTraceeEvents(cfg)...)

	rCaps = removeDupCaps(rCaps)
	return rCaps, nil
}

func getCapabilitiesRequiredByTraceeEvents(cfg *tracee.Config) []cap.Value {
	usedEvents := cfg.Filter.EventsToTrace
	for eventID := range tracee.GetEssentialEventsList(cfg) {
		usedEvents = append(usedEvents, eventID)
	}
	for eventID := range tracee.GetCaptureEventsList(cfg) {
		usedEvents = append(usedEvents, eventID)
	}
	caps := events.RequiredCapabilities(usedEvents)

	return removeDupCaps(caps)
}

// Get all capabilities required for eBPF usage (including perf buffers maps management)
func getCapabilitiesRequiredByEBPF(selfCap capabilities.ICapabilitiesSet, OSInfo IKernelVersionInfo) ([]cap.Value, error) {
	// In kernel 5.8, CAP_BPF and CAP_PERFMON capabilities were introduced in order to replace CAP_SYS_ADMIN when
	// loading eBPF programs.
	// For some reasons, some distributions using new kernels still need CAP_SYS_ADMIN,
	// so tracee still use it instead of the new capabilities.
	caps := []cap.Value{
		cap.IPC_LOCK,
		cap.SYS_RESOURCE,
		cap.SYS_ADMIN,
	}
	return caps, nil
}

func removeDupCaps(dupCaps []cap.Value) []cap.Value {
	capsMap := make(map[cap.Value]bool)
	for _, c := range dupCaps {
		capsMap[c] = true
	}
	caps := make([]cap.Value, len(capsMap))
	i := 0
	for c := range capsMap {
		caps[i] = c
		i++
	}

	return caps
}
