package integration

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/tests/testutils"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_EventsDependencies(t *testing.T) {
	assureIsRoot(t)

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
				"Remove event from state",
			},
			unexpectedEvents:  []events.ID{events.MissingKsymbol},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "non existing ksymbol dependency with sanity",
			events: []events.ID{events.MissingKsymbol, events.ExecTest},
			expectedLogs: []string{
				"Event canceled because of missing kernel symbol dependency",
				"Remove event from state",
			},
			unexpectedEvents: []events.ID{events.MissingKsymbol},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
		{
			name:   "non existing probe function",
			events: []events.ID{events.FailedAttach},
			expectedLogs: []string{
				"Cancelling event and its dependencies because of a missing probe",
				"Remove event from state",
			},
			unexpectedEvents:  []events.ID{events.FailedAttach},
			unexpectedKprobes: []string{"security_bprm_check"},
		},
		{
			name:   "non existing probe function with sanity",
			events: []events.ID{events.FailedAttach, events.ExecTest},
			expectedLogs: []string{
				"Cancelling event and its dependencies because of a missing probe",
				"Remove event from state",
			},
			unexpectedEvents: []events.ID{events.FailedAttach},
			expectedEvents:   []events.ID{events.ExecTest},
			expectedKprobes:  []string{"security_bprm_check"},
		},
	}

	// Each test will run a test binary that triggers the "exec_test" event.
	// Upon its execution, which events are evicted and which not will be tested
	createCmdEvents := func(expectedEventsIDs []events.ID, unexpectedEventsIDs []events.ID) []cmdEvents {
		expectedEvents := make([]trace.Event, len(expectedEventsIDs))
		for i, eventId := range expectedEventsIDs {
			expectedEvents[i] = createGenericEventForCmdEvents(eventId)
		}
		unexpectedEvents := make([]trace.Event, len(unexpectedEventsIDs))
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
			}
			testConfig.InitialPolicies = testutils.BuildPoliciesFromEvents(testCaseInst.events)

			ctx, cancel := context.WithCancel(context.Background())

			// set test logger
			logsDone := make(chan struct{})
			logOutChan, restoreLogger := testutils.SetTestLogger(t, logger.DebugLevel)
			logsResultChan := testutils.TestLogs(t, testCaseInst.expectedLogs, logOutChan, logsDone)

			// start tracee
			trc, err := startTracee(ctx, t, testConfig, nil, nil)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			t.Logf("  --- started tracee ---")
			err = waitForTraceeStart(trc)
			if err != nil {
				cancel()
				t.Fatal(err)
			}

			stream := trc.SubscribeAll()
			defer trc.Unsubscribe(stream)

			// start a goroutine to read events from the channel into the buffer
			buf := newEventBuffer()
			go func(ctx context.Context, buf *eventBuffer) {
				for {
					select {
					case <-ctx.Done():
						return
					case evt := <-stream.ReceiveEvents():
						buf.addEvent(evt)
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

			close(logsDone)
			if !<-logsResultChan {
				t.Logf("Test %s failed: not all logs were found", t.Name())
				failed = true
			}
		cleanup:
			// ensure that logsDone is closed
			select {
			case <-logsDone:
			default:
				close(logsDone)
			}
			restoreLogger()
			cancel()
			errStop := waitForTraceeStop(trc)
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

func createGenericEventForCmdEvents(eventId events.ID) trace.Event {
	return trace.Event{
		HostName:            anyHost,
		ProcessName:         anyComm,
		ProcessorID:         anyProcessorID,
		ProcessID:           anyPID,
		UserID:              anyUID,
		EventID:             int(eventId),
		MatchedPoliciesUser: anyPolicy,
	}
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
