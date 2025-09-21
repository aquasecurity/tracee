package main

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eFeaturesFallback struct {
	cb     detect.SignatureHandler
	osInfo *environment.OSInfo
	logger detect.Logger
}

func (sig *e2eFeaturesFallback) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	var err error
	sig.osInfo, err = environment.GetOSInfo()
	if err != nil {
		return err
	}
	sig.logger = ctx.Logger
	return nil
}

func (sig *e2eFeaturesFallback) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "FEATURES_FALLBACK_TEST",
		EventName:   "FEATURES_FALLBACK_TEST",
		Version:     "0.4.0",
		Name:        "Features Fallback Test",
		Description: "Instrumentation events E2E Tests: Features Fallback Test - Tests BPF helpers, maps (ARENA), and program types (fentry/kprobe) with architecture-aware fallback mechanism",
		Tags:        []string{"e2e", "instrumentation", "features", "fallback", "bpf", "validation", "arena"},
	}, nil
}

func (sig *e2eFeaturesFallback) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "features_fallback_test"},
	}, nil
}

func (sig *e2eFeaturesFallback) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "features_fallback_test":
		// Extract the probe_used_id argument which indicates which probe was used
		probeUsedId, err := eventObj.GetIntArgumentByName("probe_used_id")
		if err != nil {
			return fmt.Errorf("failed to get probe_used_id argument: %v", err)
		}

		// Validate the probe_used_id is within expected range
		if probeUsedId < 1 || probeUsedId > 3 {
			return fmt.Errorf("unexpected probe_used_id: %d", probeUsedId)
		}

		// Determine expected probe_used_id based on kernel capabilities
		expectedProbeId, err := sig.getExpectedProbeId()
		if err != nil {
			return fmt.Errorf("failed to determine expected probe_used_id: %v", err)
		}
		m, _ := sig.GetMetadata()

		// Check if received probe_used_id matches expected probe_used_id
		success := probeUsedId == expectedProbeId
		if !success {
			return fmt.Errorf("features fallback test failed: probe_used_id: %d, expected_probe_id: %d", probeUsedId, expectedProbeId)
		}

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data: map[string]interface{}{
				"received_probe_id": probeUsedId,
				"expected_probe_id": expectedProbeId,
				"received_desc":     getFallbackDescription(probeUsedId),
				"expected_desc":     getFallbackDescription(expectedProbeId),
				"test_result":       success,
				"kernel_version":    sig.getKernelVersion(),
			},
		})
	}

	return nil
}

func (sig *e2eFeaturesFallback) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eFeaturesFallback) Close() {}

// getFallbackDescription returns a description of what each fallback level means
func getFallbackDescription(probeUsedId int) string {
	switch probeUsedId {
	case 1:
		return "Probe 1: kprobe + ARENA map + bpf_get_current_task_btf helper (Linux 6.9+)"
	case 2:
		return "Probe 2: kprobe + bpf_get_current_task_btf helper (Linux 5.11+)"
	case 3:
		return "Probe 3: basic kprobe (universal fallback)"
	default:
		return "Unknown probe ID"
	}
}

// getKernelVersion returns the current kernel version string
func (sig *e2eFeaturesFallback) getKernelVersion() string {
	return sig.osInfo.GetOSReleaseFieldValue(environment.OS_KERNEL_RELEASE)
}

// getExpectedProbeId determines the expected probe ID based on kernel capabilities
func (sig *e2eFeaturesFallback) getExpectedProbeId() (int, error) {
	// Simple 3-level test with clear requirements:
	//
	//   Probe 1: ARENA map (6.9+) + bpf_get_current_task_btf (5.11+) = 6.9+ (ARENA limiting)
	//   Probe 2: bpf_get_current_task_btf helper (5.11+) = 5.11+ (helper limiting)
	//   Probe 3: basic kprobe (universal fallback)

	// Check Probe 1: needs ARENA (6.9+)
	comparison, err := sig.osInfo.CompareOSBaseKernelRelease("6.9.0")
	if err != nil {
		sig.logger.Errorw("error comparing kernel version for ARENA support", "err", err)
		return 3, nil
	}
	if comparison == environment.KernelVersionOlder || comparison == environment.KernelVersionEqual { // >= 6.9
		return 1, nil // Probe 1 works (ARENA map + bpf_get_current_task_btf helper)
	}

	// Check Probe 2: needs bpf_get_current_task_btf helper (5.11+)
	comparison, err = sig.osInfo.CompareOSBaseKernelRelease("5.11.0")
	if err != nil {
		sig.logger.Errorw("error comparing kernel version for helper support", "err", err)
		return 3, nil
	}
	if comparison == environment.KernelVersionOlder || comparison == environment.KernelVersionEqual { // >= 5.11 but < 6.9
		return 2, nil // Probe 2 works (bpf_get_current_task_btf helper)
	}

	return 3, nil // < 5.11, only basic kprobe works
}
