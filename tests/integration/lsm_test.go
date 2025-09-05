package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_LsmProgramSupport(t *testing.T) {
	assureIsRoot(t)
	defer goleak.VerifyNone(t)

	lsmSupported := isLsmSupported()
	t.Logf("LSM support detected: %v", lsmSupported)

	if lsmSupported {
		t.Run("LSM_supported", func(t *testing.T) {
			testLsmEventGeneration(t)
		})
	} else {
		t.Run("LSM_not_supported", func(t *testing.T) {
			testLsmProbeCancellation(t)
		})
	}
}

func testLsmEventGeneration(t *testing.T) {
	t.Log("Testing LSM event generation on supported kernel")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup and start Tracee
	trc, buf, err := setupTraceeForLsmTest(ctx, t)
	if err != nil {
		t.Fatalf("Failed to setup Tracee: %v", err)
	}
	defer cleanupLsmTest(t, trc, cancel)

	// Execute commands that should trigger LSM events
	if err := triggerLsmEvents(t, buf); err != nil {
		t.Fatalf("Failed to trigger and validate LSM events: %v", err)
	}

	t.Log("Successfully validated LSM event generation")
}

func testLsmProbeCancellation(t *testing.T) {
	t.Log("Testing LSM probe cancellation on unsupported kernel")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup logging to capture cancellation messages
	logsDone := make(chan struct{})

	// Use a single combined search pattern like other tests to avoid timing issues
	expectedLogs := []string{
		"Event failed due to incompatible probe\",\"event\":\"lsm_test",
	}

	logOutChan, restoreLogger := testutils.SetTestLogger(t, logger.DebugLevel)
	defer restoreLogger()

	logsResultChan := testutils.TestLogs(t, expectedLogs, logOutChan, logsDone)

	// Setup and start Tracee (should fail to load LSM probe)
	trc, _, err := setupTraceeForLsmTest(ctx, t)
	if err != nil {
		t.Fatalf("Failed to setup Tracee: %v", err)
	}
	defer cleanupLsmTest(t, trc, cancel)

	// Give more time for initialization and log processing
	time.Sleep(5 * time.Second)

	// Close logsDone to signal TestLogs to finish processing
	close(logsDone)

	// Validate that expected logs were found with timeout
	select {
	case result := <-logsResultChan:
		if !result {
			t.Fatal("Expected probe cancellation logs were not found")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for log validation results")
	}

	t.Log("Successfully validated LSM probe cancellation")
}

// setupTraceeForLsmTest configures and starts Tracee for LSM testing
func setupTraceeForLsmTest(ctx context.Context, t *testing.T) (*tracee.Tracee, *eventBuffer, error) {
	t.Helper()

	// Create Tracee configuration
	testConfig, err := createLsmTestConfig()
	if err != nil {
		return nil, nil, err
	}

	// Start Tracee
	trc, err := startTracee(ctx, t, testConfig, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	if err := waitForTraceeStart(trc); err != nil {
		return nil, nil, err
	}

	// Setup event collection
	stream := trc.SubscribeAll()
	buf := newEventBuffer()

	// Start event collection goroutine
	go func(ctx context.Context, buf *eventBuffer) {
		defer trc.Unsubscribe(stream)
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-stream.ReceiveEvents():
				buf.addEvent(evt)
			}
		}
	}(ctx, buf)

	t.Log("Tracee started successfully for LSM testing")
	return trc, buf, nil
}

// cleanupLsmTest properly shuts down Tracee and handles cleanup
func cleanupLsmTest(t *testing.T, trc *tracee.Tracee, cancel context.CancelFunc) {
	t.Helper()

	if cancel != nil {
		cancel()
	}

	if trc != nil {
		if err := waitForTraceeStop(trc); err != nil {
			t.Logf("Warning: Error stopping Tracee: %v", err)
		} else {
			t.Log("Tracee stopped successfully")
		}
	}
}

// triggerLsmEvents executes file operations and validates LSM event generation
func triggerLsmEvents(t *testing.T, buf *eventBuffer) error {
	t.Helper()

	expectedEvent := createGenericEventForCmdEvents(events.LsmTest)

	testCommands := []cmdEvents{
		{
			runCmd:  "touch /tmp/lsm_test_file",
			timeout: time.Second,
		},
		{
			runCmd:         "cat /tmp/lsm_test_file",
			waitFor:        time.Second,
			timeout:        3 * time.Second,
			expectedEvents: []trace.Event{expectedEvent},
		},
		{
			runCmd:  "rm -f /tmp/lsm_test_file",
			timeout: time.Second,
		},
	}

	return ExpectAtLeastOneForEach(t, testCommands, buf, false)
}

// createLsmTestConfig creates a Tracee configuration for LSM testing
func createLsmTestConfig() (config.Config, error) {
	osInfo, err := environment.GetOSInfo()
	if err != nil {
		return config.Config{}, err
	}

	testConfig := config.Config{
		Capabilities: &config.CapabilitiesConfig{
			BypassCaps: true,
		},
		OSInfo: osInfo,
	}

	// Build policies for LSM test event
	policies := testutils.BuildPoliciesFromEvents([]events.ID{events.LsmTest})
	initialPolicies := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		initialPolicies = append(initialPolicies, p)
	}
	testConfig.InitialPolicies = initialPolicies

	return testConfig, nil
}

// isLsmSupported checks if the current kernel supports LSM BPF programs
func isLsmSupported() bool {
	// Check if BPF_PROG_TYPE_LSM is supported
	supported, err := bpf.BPFProgramTypeIsSupported(bpf.BPFProgTypeLsm)
	if err != nil {
		return false
	}
	if !supported {
		return false
	}

	// Check if LSM is supported
	supported, err = environment.CheckLSMSupport(os.DirFS("/"), func(option environment.KernelConfigOption) (environment.KernelConfigOptionValue, string, error) {
		kernelConfig, err := environment.InitKernelConfig()
		if err != nil {
			return environment.UNDEFINED, "", err
		}
		if err := kernelConfig.LoadKernelConfig(); err != nil {
			return environment.UNDEFINED, "", err
		}
		value := kernelConfig.GetValue(option)
		if value == environment.STRING {
			strValue, err := kernelConfig.GetValueString(option)
			if err != nil {
				return environment.UNDEFINED, "", err
			}
			return environment.STRING, strValue, nil
		}
		return value, value.String(), nil
	})
	if err != nil {
		return false
	}
	return supported
}
