package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/syndtr/gocapability/capability"
)

// IKernelVersionInfo is an interface to check kernel version
type IKernelVersionInfo interface {
	// CompareOSBaseKernelRelease compare given kernel version to current one.
	// The return value is -1, 0 or 1 if given version is less,
	// equal or bigger, respectively, than running one.
	CompareOSBaseKernelRelease(string) int
}

const bpfCapabilitiesMinKernelVersion = "5.8"

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
func generateTraceeEbpfRequiredCapabilities(OSInfo IKernelVersionInfo, cfg *tracee.Config, selfCap capability.Capabilities) (
	[]capability.Cap, error) {
	rCaps, err := getCapabilitiesRequiredByEBPF(selfCap, OSInfo)
	if err != nil {
		return nil, err
	}
	rCaps = append(rCaps, getCapabilitiesRequiredByTraceeEvents(cfg)...)

	rCaps = removeDupCaps(rCaps)
	return rCaps, nil
}

func getCapabilitiesRequiredByTraceeEvents(cfg *tracee.Config) []capability.Cap {
	usedEvents := cfg.Filter.EventsToTrace
	for eventID := range tracee.GetEssentialEventsList(cfg) {
		usedEvents = append(usedEvents, eventID)
	}
	for eventID := range tracee.GetCaptureEventsList(cfg) {
		usedEvents = append(usedEvents, eventID)
	}
	caps := tracee.GetCapabilitiesRequiredByEvents(usedEvents)

	return removeDupCaps(caps)
}

// Get all capabilities required for eBPF usage (including perf buffers maps management)
func getCapabilitiesRequiredByEBPF(selfCap capability.Capabilities, OSInfo IKernelVersionInfo) ([]capability.Cap, error) {
	caps := []capability.Cap{
		capability.CAP_IPC_LOCK,
		capability.CAP_SYS_RESOURCE,
	}
	var versCaps []capability.Cap
	if OSInfo.CompareOSBaseKernelRelease(bpfCapabilitiesMinKernelVersion) <= 0 {
		versCaps = []capability.Cap{
			capability.CAP_BPF,
			capability.CAP_PERFMON,
		}
		if err1 := capabilities.CheckRequired(selfCap, versCaps); err1 != nil {
			versCaps = []capability.Cap{
				capability.CAP_SYS_ADMIN,
			}
			if err2 := capabilities.CheckRequired(selfCap, versCaps); err2 != nil {
				return nil, fmt.Errorf("missing capabilites required for eBPF program loading - either CAP_BPF + CAP_PERFMON or CAP_SYS_ADMIN")
			}
		}
	} else {
		versCaps = []capability.Cap{
			capability.CAP_SYS_ADMIN,
		}
	}
	caps = append(caps, versCaps...)
	return caps, nil
}

func removeDupCaps(dupCaps []capability.Cap) []capability.Cap {
	capsMap := make(map[capability.Cap]bool)
	for _, c := range dupCaps {
		capsMap[c] = true
	}
	caps := make([]capability.Cap, len(capsMap))
	i := 0
	for c := range capsMap {
		caps[i] = c
		i++
	}

	return caps
}
