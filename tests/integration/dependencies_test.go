package integration

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

func Test_EventsDependencies(t *testing.T) {
	testutils.AssureIsRoot(t)

	// Make sure we don't leak any goroutines since we run Tracee many times in this test.
	// If a test case fails, ignore the leak since it's probably caused by the aborted test.
	defer goleak.VerifyNone(t)

	// TODO: Check that probes are really removed if not used anymore
	testCases := []struct {
		name              string
		events            []events.ID
		expectedLogs      []string
		expectedEvents    []events.ID
		unexpectedEvents  []events.ID
		expectedKprobes   []string
		unexpectedKprobes []string
	}{
		{
			name:            "sanity of exec test event",
			events:          []events.ID{events.ExecTest},
			expectedEvents:  []events.ID{events.ExecTest},
			expectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "non existing ksymbol dependency",
			events: []events.ID{events.MissingKsymbol},
			expectedLogs: []string{
				"Event canceled because of missing kernel symbol dependency",
				"Remove event from rules",
			},
			unexpectedEvents:  []events.ID{events.MissingKsymbol},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "non existing ksymbol dependency with sanity",
			events: []events.ID{events.MissingKsymbol, events.ExecTest},
			expectedLogs: []string{
				"Event canceled because of missing kernel symbol dependency",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.MissingKsymbol},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "non existing probe function",
			events: []events.ID{events.FailedAttach},
			expectedLogs: []string{
				"All fallbacks failed, removing event",
				"Remove event from rules",
			},
			unexpectedEvents:  []events.ID{events.FailedAttach},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "non existing probe function with sanity",
			events: []events.ID{events.FailedAttach, events.ExecTest},
			expectedLogs: []string{
				"All fallbacks failed, removing event",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.FailedAttach},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "incompatible probe test",
			events: []events.ID{events.IncompatibleProbeTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"Remove event from rules",
			},
			unexpectedEvents:  []events.ID{events.IncompatibleProbeTest},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "incompatible probe with sanity",
			events: []events.ID{events.IncompatibleProbeTest, events.ExecTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.IncompatibleProbeTest},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "incompatible probe with fallback",
			events: []events.ID{events.IncompatibleProbeWithFallbackTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"Failing event",
				"Successfully switched to fallback\",\"event\":\"incompatible_probe_with_fallback_test",
			},
			expectedEvents:  []events.ID{events.IncompatibleProbeWithFallbackTest},
			expectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "incompatible probe with fallback and sanity",
			events: []events.ID{events.IncompatibleProbeWithFallbackTest, events.ExecTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"Failing event",
				"Successfully switched to fallback\",\"event\":\"incompatible_probe_with_fallback_test",
			},
			expectedEvents:  []events.ID{events.IncompatibleProbeWithFallbackTest, events.ExecTest},
			expectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "failed event dependency",
			events: []events.ID{events.FailedEventDependencyTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"All fallbacks failed, removing event\",\"event\":\"failed_event_dependency_test",
				"Remove event from rules",
			},
			unexpectedEvents:  []events.ID{events.FailedEventDependencyTest},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "failed event dependency with sanity",
			events: []events.ID{events.FailedEventDependencyTest, events.ExecTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"All fallbacks failed, removing event\",\"event\":\"failed_event_dependency_test",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.FailedEventDependencyTest},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "multiple fallbacks event",
			events: []events.ID{events.MultipleFallbacksTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"All fallbacks failed, removing event\",\"event\":\"failed_event_dependency_test",
				"Event canceled because of missing kernel symbol dependency",
				"Successfully switched to fallback\",\"event\":\"multiple_fallbacks_test",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.IncompatibleProbeTest, events.FailedEventDependencyTest},
			expectedEvents:   []events.ID{events.MultipleFallbacksTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "multiple fallbacks event with sanity",
			events: []events.ID{events.MultipleFallbacksTest, events.ExecTest},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"All fallbacks failed, removing event\",\"event\":\"incompatible_probe_test",
				"All fallbacks failed, removing event\",\"event\":\"failed_event_dependency_test",
				"Event canceled because of missing kernel symbol dependency",
				"Successfully switched to fallback\",\"event\":\"multiple_fallbacks_test",
				"Remove event from rules",
			},
			unexpectedEvents: []events.ID{events.IncompatibleProbeTest},
			expectedEvents:   []events.ID{events.ExecTest, events.MultipleFallbacksTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "shared probe events with incompatible probe",
			events: []events.ID{events.SharedProbeEventA, events.SharedProbeEventB},
			expectedLogs: []string{
				"Probe failed due to incompatible probe",
				"Successfully switched to fallback\",\"event\":\"shared_probe_event_a",
				"Successfully switched to fallback\",\"event\":\"shared_probe_event_b",
			},
			unexpectedEvents: []events.ID{events.IncompatibleProbeTest},
			expectedEvents:   []events.ID{events.SharedProbeEventA, events.SharedProbeEventB},
			expectedKprobes:  []string{"security_bprm_check"},
		},
	}

	// Each test will run a test binary that triggers the "exec_test" event.
	// Upon its execution, which events are evicted and which not will be tested
	createCmdEvents := func(expectedEventsIDs []events.ID, unexpectedEventsIDs []events.ID) []cmdEvents {
		expectedEvents := make([]*pb.Event, len(expectedEventsIDs))
		for i, eventId := range expectedEventsIDs {
			expectedEvents[i] = createGenericEventForCmdEvents(eventId)
		}
		unexpectedEvents := make([]*pb.Event, len(unexpectedEventsIDs))
		for i, eventId := range unexpectedEventsIDs {
			unexpectedEvents[i] = createGenericEventForCmdEvents(eventId)
		}
		return []cmdEvents{
			{
				runCmd:  "cp /bin/ls /tmp/test",
				timeout: time.Second,
			},
			{
				runCmd:           "/tmp/test",
				waitFor:          time.Second,
				timeout:          3 * time.Second,
				expectedEvents:   expectedEvents,
				unexpectedEvents: unexpectedEvents,
			},
			{
				runCmd:  "rm /tmp/test",
				timeout: time.Second,
			},
		}
	}

	for _, testCaseInst := range testCases {
		t.Run(testCaseInst.name, func(t *testing.T) {
			// prepare tracee config
			testConfig := config.Config{
				Capabilities: &config.CapabilitiesConfig{
					BypassCaps: true,
				},
				NoContainersEnrich: true,
			}
			// Initialize OSInfo to prevent nil pointer dereference in probes compatibility
			osInfo, err := environment.GetOSInfo()
			if err != nil {
				t.Fatalf("Failed to get OS info: %v", err)
			}
			testConfig.OSInfo = osInfo

			ps := testutils.BuildPoliciesFromEvents(testCaseInst.events)
			initialPolicies := make([]interface{}, 0, len(ps))
			for _, p := range ps {
				initialPolicies = append(initialPolicies, p)
			}
			testConfig.InitialPolicies = initialPolicies

			ctx, cancel := context.WithCancel(context.Background())

			// set test logger
			logsDone := make(chan struct{})
			var logsDoneOnce sync.Once
			closeLogsDone := func() {
				logsDoneOnce.Do(func() {
					close(logsDone)
				})
			}

			logOutChan, restoreLogger := testutils.SetTestLogger(t, logger.DebugLevel)
			logsResultChan := testutils.TestLogs(t, testCaseInst.expectedLogs, logOutChan, logsDone)
			defer closeLogsDone()

			// start tracee
			trc, err := testutils.StartTracee(ctx, t, testConfig, nil, nil)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			t.Logf("  --- started tracee ---")
			err = testutils.WaitForTraceeStart(trc)
			if err != nil {
				cancel()
				t.Fatal(err)
			}

			stream := trc.SubscribeAll()
			defer trc.Unsubscribe(stream)

			// start a goroutine to read events from the channel into the buffer
			buf := testutils.NewEventBuffer()
			go func(ctx context.Context, buf *testutils.EventBuffer) {
				for {
					select {
					case <-ctx.Done():
						return
					case pbEvent := <-stream.ReceiveEvents():
						if pbEvent != nil {
							buf.AddEvent(pbEvent)
						}
					}
				}
			}(ctx, buf)

			var failed bool
			var testCmdEvents []cmdEvents

			// test kprobes
			err = testAttachedKprobes(testCaseInst.expectedKprobes, testCaseInst.unexpectedKprobes)
			if err != nil {
				t.Logf("Test %s failed: %v", t.Name(), err)
				failed = true
				goto cleanup
			}

			// test events
			testCmdEvents = createCmdEvents(testCaseInst.expectedEvents, testCaseInst.unexpectedEvents)
			err = ExpectAtLeastOneForEach(t, testCmdEvents, buf, false)
			if err != nil {
				t.Logf("Test %s failed: %v", t.Name(), err)
				failed = true
				goto cleanup
			}

		cleanup:
			// ensure that logsDone is closed
			closeLogsDone()
			if !<-logsResultChan { // always consume the result channel
				if !failed {
					t.Logf("Test %s failed: not all logs were found", t.Name())
					failed = true
				}
			}
			restoreLogger()
			cancel()
			errStop := testutils.WaitForTraceeStop(trc)
			if errStop != nil {
				t.Log(errStop)
				failed = true
			} else {
				t.Logf("  --- stopped tracee ---")
			}

			if failed {
				t.Fail()
			}
		})
	}
}

func createGenericEventForCmdEvents(eventId events.ID) *pb.Event {
	return expectPbEvent(anyHost, anyComm, anyProcessorID, anyPID, anyUID, eventId, nil)
}

func GetAttachedKprobes() ([]string, error) {
	cmd := exec.Command("cat", "/sys/kernel/debug/kprobes/list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute bpftool: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	probes := make([]string, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			probe := fields[2]
			plusIndex := strings.Index(probe, "+")
			if plusIndex != -1 {
				probe = probe[:plusIndex]
			}
			probes = append(probes, probe)
		}
	}

	return probes, nil
}

func testAttachedKprobes(expectedKprobes []string, unexpectedKprobes []string) error {
	// Get the initial list of kprobes
	attachedKprobes, err := GetAttachedKprobes()
	if err != nil {
		return err
	}

	// Check if the expected kprobes were added
	for _, probe := range expectedKprobes {
		if !slices.Contains(attachedKprobes, probe) {
			return fmt.Errorf("expected kprobe %s not found", probe)
		}
	}

	// Check if the unexpected kprobes were added
	for _, probe := range unexpectedKprobes {
		if slices.Contains(attachedKprobes, probe) {
			return fmt.Errorf("unexpected kprobe %s found", probe)
		}
	}

	return nil
}
