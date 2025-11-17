package compatibility

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

func TestCompatibility(t *testing.T) {
	defer goleak.VerifyNone(t)

	testutils.AssureIsRoot(t)

	expectedProbeId := getExpectedProbeId(t)

	failed := false

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Define policy with fallback features test
	policies := testutils.BuildPoliciesFromEvents([]events.ID{events.FeaturesFallbackTest})

	// For integration tests, tracee runs as a library inside the test binary,
	// so uprobes need to attach to /proc/self/exe (the test binary itself)
	// However, during test compilation, the test binary gets the symbols
	testBinaryPath := os.Args[0] // Get the actual test binary path
	t.Logf("  --- test binary path: %s ---", testBinaryPath)

	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		NoContainersEnrich: true,
		BPFObjPath:         testBinaryPath, // Use test binary for uprobe attachment
	}

	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}
	cfg.InitialPolicies = initialPolicies

	eventBuffer := testutils.NewEventBuffer()

	// Start Tracee
	t.Logf("  --- started tracee ---")
	traceeInstance, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = testutils.WaitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	t.Logf("  --- tracee started successfully ---")

	// Give time for probes to attach
	time.Sleep(500 * time.Millisecond)

	// Debug: Check probe attachment status
	debugProbeAttachments(t, traceeInstance)
	debugEventDependencies(t, traceeInstance)

	eventStream := traceeInstance.SubscribeAll()
	defer traceeInstance.Unsubscribe(eventStream)

	go func() {
		for {
			select {
			case event := <-eventStream.ReceiveEvents():
				eventBuffer.AddEvent(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Give a moment for the uprobe to fire and event processing to fully initialize
	time.Sleep(2 * time.Second)
	// Trigger the features fallback test event multiple times to ensure it fires
	t.Logf("  --- triggering features fallback test ---")
	traceeInstance.TriggerFeaturesFallbackTest()

	err = testutils.WaitForTraceeOutputEvents(t, 10*time.Second, eventBuffer, 1, true)

	// Fail the test now to ensure proper cleanup
	if err != nil {
		t.Logf("  --- error waiting for events: %v ---", err)
		failed = true
	}

	capturedEvents := eventBuffer.GetCopy()

	if len(capturedEvents) > 0 {
		foundFeaturesFallback := false
		usedProbeId := 0
		for _, event := range capturedEvents {
			if event.EventID == int(events.FeaturesFallbackTest) {
				foundFeaturesFallback = true
				usedProbeId, err = event.GetIntArgumentByName("probe_used_id")
				if err != nil {
					failed = true
				}
				break
			}
		}

		assert.True(t, foundFeaturesFallback, "Features fallback test event not found")
		assert.Equal(t, expectedProbeId, usedProbeId, "Expected probe ID (%d) does not match used probe ID (%d)", expectedProbeId, usedProbeId)
	}

	cancel()
	errStop := testutils.WaitForTraceeStop(traceeInstance)
	if errStop != nil {
		t.Log(errStop)
		failed = true
	} else {
		t.Logf("  --- stopped tracee ---")
	}

	if failed {
		t.Fail()
	}
}

// handleSupportCheck runs a support check function, handles error and logs appropriately.
func handleSupportCheck(t *testing.T, checkFunc func() (bool, error), name string) bool {
	supported, err := checkFunc()
	if err != nil {
		if !supported {
			supported = false
			t.Logf("%s not supported: %v", name, err)
		} else {
			t.Logf("%s supported (with spurious errno: %v)", name, err)
			supported = true
		}
	}
	return supported
}

func getExpectedProbeId(t *testing.T) int {
	// Simple 3-level test with clear requirements:
	//
	//   Probe 1: ARENA map (6.9+) + bpf_get_current_task_btf (5.11+) = 6.9+ (ARENA limiting)
	//   Probe 2: bpf_get_current_task_btf helper (5.11+) = 5.11+ (helper limiting)
	//   Probe 3: basic kprobe (universal fallback)
	arenaSupported := handleSupportCheck(
		t,
		func() (bool, error) { return bpf.BPFMapTypeIsSupported(bpf.MapTypeArena) },
		"ARENA map type",
	)
	helperSupported := handleSupportCheck(
		t,
		func() (bool, error) {
			return bpf.BPFHelperIsSupported(bpf.BPFProgTypeKprobe, bpf.BPFFuncGetCurrentTaskBtf)
		},
		"bpf_get_current_task_btf helper",
	)

	if arenaSupported && helperSupported {
		return 1
	}

	if helperSupported {
		return 2
	}

	return 3
}

// debugProbeAttachments uses reflection to inspect the private defaultProbes field
// and log the attachment status of the features fallback test probes
func debugProbeAttachments(t *testing.T, traceeInstance interface{}) {
	t.Logf("  --- checking probe attachments ---")

	// Use reflection to access the private defaultProbes field
	traceeValue := reflect.ValueOf(traceeInstance).Elem()
	defaultProbesField := traceeValue.FieldByName("defaultProbes")

	if !defaultProbesField.IsValid() {
		t.Logf("  !!! Could not access defaultProbes field")
		return
	}

	// Make the private field accessible
	defaultProbesField = reflect.NewAt(defaultProbesField.Type(), defaultProbesField.Addr().UnsafePointer()).Elem()

	if defaultProbesField.IsNil() {
		t.Logf("  !!! defaultProbes is nil")
		return
	}

	// Check each of the three features fallback probes
	featureProbes := []struct {
		handle probes.Handle
		name   string
	}{
		{probes.FeaturesFallbackArena, "FeaturesFallbackArena (Level 1: ARENA map + bpf_get_current_task_btf helper)"},
		{probes.FeaturesFallbackHelper, "FeaturesFallbackHelper (Level 2: bpf_get_current_task_btf helper)"},
		{probes.FeaturesFallbackMinimal, "FeaturesFallbackMinimal (Level 3: basic uprobe)"},
	}

	for _, fp := range featureProbes {
		// Call GetProbeByHandle method using reflection
		getProbeMethod := defaultProbesField.MethodByName("GetProbeByHandle")
		if !getProbeMethod.IsValid() {
			t.Logf("  !!! Could not find GetProbeByHandle method")
			continue
		}

		results := getProbeMethod.Call([]reflect.Value{reflect.ValueOf(fp.handle)})
		if len(results) == 0 || results[0].IsNil() {
			t.Logf("  [%s] handle=%d: NOT FOUND in probe group", fp.name, fp.handle)
			continue
		}

		probe := results[0]

		// Try type assertion to access IsAttached() - FixedUprobe specifically
		probeInterface := probe.Interface()

		// Type assert to *FixedUprobe to access IsAttached()
		if fixedUprobe, ok := probeInterface.(*probes.FixedUprobe); ok {
			isAttached := fixedUprobe.IsAttached()
			status := "❌ NOT ATTACHED"
			if isAttached {
				status = "✅ ATTACHED"
			}
			t.Logf("  [%s] handle=%d: %s", fp.name, fp.handle, status)
			continue
		}

		// Fallback: try reflection-based method call
		isAttachedMethod := probe.MethodByName("IsAttached")
		if isAttachedMethod.IsValid() {
			attachResults := isAttachedMethod.Call([]reflect.Value{})
			if len(attachResults) > 0 {
				isAttached := attachResults[0].Bool()
				status := "❌ NOT ATTACHED"
				if isAttached {
					status = "✅ ATTACHED"
				}
				t.Logf("  [%s] handle=%d: %s", fp.name, fp.handle, status)
			}
		} else {
			t.Logf("  [%s] handle=%d: probe exists (type: %T)", fp.name, fp.handle, probeInterface)
		}
	}

	t.Logf("  --- done checking probe attachments ---")
}

// debugEventDependencies uses reflection to inspect the event dependencies
// and log which probes should be attached for the features fallback test event
func debugEventDependencies(t *testing.T, traceeInstance interface{}) {
	t.Logf("  --- checking event dependencies ---")

	// Use reflection to access the private eventsDependencies field
	traceeValue := reflect.ValueOf(traceeInstance).Elem()
	eventsDepsField := traceeValue.FieldByName("eventsDependencies")

	if !eventsDepsField.IsValid() {
		t.Logf("  !!! Could not access eventsDependencies field")
		return
	}

	// Make the private field accessible
	eventsDepsField = reflect.NewAt(eventsDepsField.Type(), eventsDepsField.Addr().UnsafePointer()).Elem()

	if eventsDepsField.IsNil() {
		t.Logf("  !!! eventsDependencies is nil")
		return
	}

	// Call GetProbes() method to see which probes are registered
	getProbesMethod := eventsDepsField.MethodByName("GetProbes")
	if !getProbesMethod.IsValid() {
		t.Logf("  !!! Could not find GetProbes method")
		return
	}

	results := getProbesMethod.Call([]reflect.Value{})
	if len(results) == 0 {
		t.Logf("  !!! GetProbes returned no results")
		return
	}

	probeHandles := results[0]
	if !probeHandles.IsValid() || probeHandles.IsNil() {
		t.Logf("  !!! GetProbes returned invalid/nil slice")
		return
	}

	t.Logf("  Total probe dependencies registered: %d", probeHandles.Len())
	t.Logf("  Note: Feature fallback probes use compatibility-based selection,")
	t.Logf("        so only one of the three variants will be attached based on kernel capabilities")

	t.Logf("  --- done checking event dependencies ---")
}

// TestClockDetection validates that Tracee correctly detects and uses the appropriate
// clock type (BOOTTIME or MONOTONIC) based on kernel BPF helper support.
//
// On kernels from 5.8: bpf_ktime_get_boot_ns is available → CLOCK_BOOTTIME
// On kernels before 5.8: bpf_ktime_get_boot_ns is unavailable → CLOCK_MONOTONIC
func TestClockDetection(t *testing.T) {
	defer goleak.VerifyNone(t)

	testutils.AssureIsRoot(t)

	// Step 1: Check what the current kernel actually supports
	t.Logf("  --- detecting kernel BPF clock support ---")

	boottimeSupported := handleSupportCheck(
		t,
		func() (bool, error) {
			return bpf.BPFHelperIsSupported(
				bpf.BPFProgTypeKprobe,
				bpf.BPFFuncKtimeGetBootNs,
			)
		},
		"bpf_ktime_get_boot_ns helper",
	)

	// Step 2: Determine expected clock based on kernel support
	var expectedClockName string
	var expectedClockID int32

	if boottimeSupported {
		expectedClockID = timeutil.CLOCK_BOOTTIME
		expectedClockName = "CLOCK_BOOTTIME"
		t.Logf("  ✅ Kernel supports bpf_ktime_get_boot_ns → expecting CLOCK_BOOTTIME")
	} else {
		expectedClockID = timeutil.CLOCK_MONOTONIC
		expectedClockName = "CLOCK_MONOTONIC"
		t.Logf("  ⚠️  Kernel does NOT support bpf_ktime_get_boot_ns → expecting CLOCK_MONOTONIC")
	}

	// Step 3: Initialize Tracee (which triggers clock detection in timeutil.Init)
	t.Logf("  --- starting tracee to test clock detection ---")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		NoContainersEnrich: true,
	}

	// Use a minimal policy to avoid unnecessary overhead
	policies := testutils.BuildPoliciesFromEvents([]events.ID{})
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}
	cfg.InitialPolicies = initialPolicies

	traceeInstance, err := testutils.StartTracee(ctx, t, cfg, nil, nil)
	require.NoError(t, err, "Failed to start Tracee")

	err = testutils.WaitForTraceeStart(traceeInstance)
	require.NoError(t, err, "Tracee failed to start")

	t.Logf("  --- tracee started successfully ---")

	// Step 4: Verify Tracee detected and is using the correct clock
	t.Logf("  --- verifying clock selection ---")

	// The clock is set during Tracee initialization via timeutil.Init()
	// We can verify this using the public timeutil.GetUsedClockID() API
	actualClockID := timeutil.GetUsedClockID()

	var actualClockName string
	if actualClockID == timeutil.CLOCK_BOOTTIME {
		actualClockName = "CLOCK_BOOTTIME"
	} else if actualClockID == timeutil.CLOCK_MONOTONIC {
		actualClockName = "CLOCK_MONOTONIC"
	} else {
		actualClockName = "UNKNOWN"
	}

	t.Logf("  Expected clock: %s (ID: %d)", expectedClockName, expectedClockID)
	t.Logf("  Actual clock:   %s (ID: %d)", actualClockName, actualClockID)

	// Assert that the detected clock matches kernel capability
	assert.Equal(t, expectedClockID, actualClockID,
		"Tracee should detect and use %s based on kernel support for bpf_ktime_get_boot_ns",
		expectedClockName)

	if actualClockID == expectedClockID {
		t.Logf("  ✅ Clock detection CORRECT: Using %s as expected", actualClockName)
	} else {
		t.Logf("  ❌ Clock detection MISMATCH: Expected %s but got %s",
			expectedClockName, actualClockName)
	}

	t.Logf("  Note: This clock is used for all BPF timestamp conversions and procfs hash calculations")

	// Step 5: Cleanup
	cancel()
	err = testutils.WaitForTraceeStop(traceeInstance)
	assert.NoError(t, err, "Tracee should stop cleanly")

	t.Logf("  --- stopped tracee ---")
}
