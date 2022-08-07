package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

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
	rCaps, err := getCapabilitiesRequiredByEBPF(OSInfo, cfg.Debug)
	if err != nil {
		return nil, err
	}
	rCaps = append(rCaps, getCapabilitiesRequiredByTraceeEvents(cfg)...)

	rCaps = removeDupCaps(rCaps)
	return rCaps, nil
}

func getCapabilitiesRequiredByTraceeEvents(cfg *tracee.Config) []cap.Value {
	usedEvents := cfg.Filter.EventsToTrace
	for eventID := range tracee.GetEssentialEventsList() {
		usedEvents = append(usedEvents, eventID)
	}
	for eventID := range tracee.GetCaptureEventsList(*cfg) {
		usedEvents = append(usedEvents, eventID)
	}
	caps := events.RequiredCapabilities(usedEvents)

	return removeDupCaps(caps)
}

// Retrieve the value of the kernel parameter perf_event_paranoid
func getKernelPerfEventParanoidValue() (int, error) {
	/*
	* perf event paranoia level:
	*  -1 - not paranoid at all
	*   0 - disallow raw tracepoint access for unpriv
	*   1 - disallow cpu events for unpriv
	*   2 - disallow kernel profiling for unpriv
	*   4 - disallow all unpriv perf event use (Only on some particular distributions)
	 */
	const MaxParanoiaLevel = 4
	value, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		return MaxParanoiaLevel, errors.New("cannot read kernel paranoia")
	}
	intVal, err := strconv.ParseInt(strings.TrimSuffix(string(value), "\n"), 0, 16)
	if err != nil {
		return MaxParanoiaLevel, errors.New("cannot handle kernel paranoia")
	}
	return int(intVal), nil
}

// getCapabilitiesRequiredByEBPF gets all capabilities required for eBPF usage (including perf buffers maps management)
func getCapabilitiesRequiredByEBPF(OSInfo KernelVersionInfo, debug bool) ([]cap.Value, error) {
	// In kernel 5.8, CAP_BPF and CAP_PERFMON capabilities were introduced in
	// order to replace CAP_SYS_ADMIN when loading eBPF programs.
	privilegedCaps := []cap.Value{
		cap.IPC_LOCK,
		cap.SYS_RESOURCE,
		cap.SYS_ADMIN,
	}
	unprivilegedCaps := []cap.Value{
		cap.IPC_LOCK,
		cap.SYS_RESOURCE,
		cap.BPF,
		cap.PERFMON,
	}
	kernelParanoidValue, err := getKernelPerfEventParanoidValue()
	if err != nil {
		if debug {
			fmt.Println("Paranoid: could not read /proc/sys/kernel/perf_event_paranoid: ", err.Error())
		}
		return privilegedCaps, nil
	}
	const BpfCapabilitiesMinKernelVersion = "5.8"
	if OSInfo.CompareOSBaseKernelRelease(BpfCapabilitiesMinKernelVersion) < 0 {
		// if kernelParanoidValue is too high, CAP_SYS_ADMIN is required
		if kernelParanoidValue > 3 {
			if debug {
				fmt.Println("Paranoid: Value in /proc/sys/kernel/perf_event_paranoid is > 3")
				fmt.Println("Paranoid: Tracee needs CAP_SYS_ADMIN instead of CAP_BPF + CAP_PERFMON")
				fmt.Println("Paranoid: To change that behavior set perf_event_paranoid to 3 or less.")
			}
			return privilegedCaps, nil
		} else {
			err := capabilities.CheckRequired(unprivilegedCaps)
			if err != nil {
				return privilegedCaps, nil
			}
			return unprivilegedCaps, nil
		}
	}
	return privilegedCaps, nil
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
