package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// KernelVersionInfo is an interface to check kernel version
type KernelVersionInfo interface {
	// CompareOSBaseKernelRelease compare given kernel version to current one.
	// The return value is -1, 0 or 1 if given version is less,
	// equal or bigger, respectively, than running one.
	CompareOSBaseKernelRelease(string) int
}

// ensureCapabilities makes sure program runs with required capabilities only
func ensureCapabilities(OSInfo KernelVersionInfo, cfg *tracee.Config, allowHighCapabilities bool) error {
	rCaps, err := generateTraceeEbpfRequiredCapabilities(OSInfo, cfg)
	if err != nil {
		return err
	}

	if err := capabilities.CheckRequired(rCaps); err != nil {
		if errors.Is(err, &capabilities.MissingCapabilitiesError{}) {
			return err
		} else {
			// This is not fatal, because the drop capabilities function will just fail if some capabilities are missing
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}

	if err = capabilities.DropUnrequired(rCaps); err != nil {
		if !allowHighCapabilities {
			return fmt.Errorf("%w - to avoid this error use the --%s flag", err, allowHighCapabilitiesFlag)
		} else if cfg.Debug {
			fmt.Fprintf(os.Stderr, "Failed in dropping capabilities - %v\n", err)
			fmt.Fprintf(os.Stderr, "Continue with high capabilities accoridng to the configuration\n")
		}
	}

	return nil
}

// Get all capabilities required to run tracee-ebpf for current run
func generateTraceeEbpfRequiredCapabilities(OSInfo KernelVersionInfo, cfg *tracee.Config) (
	[]cap.Value, error) {
	rCaps, err := getCapabilitiesRequiredByEBPF(OSInfo)
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
func getCapabilitiesRequiredByEBPF(OSInfo KernelVersionInfo) ([]cap.Value, error) {
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
