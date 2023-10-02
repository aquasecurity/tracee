package perftests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tests/testutils"
)

var metrics = []string{
	"tracee_ebpf_bpf_logs_total",
	"tracee_ebpf_errors_total",
	"tracee_ebpf_events_filtered",
	"tracee_ebpf_events_total",
	"tracee_ebpf_lostevents_total",
	"tracee_ebpf_network_capture_events_total",
	"tracee_ebpf_network_capture_lostevents_total",
	"tracee_ebpf_write_lostevents_total",
}

// checkIfMetricsExist checks if all metrics exist in the metrics endpoint.
func checkIfMetricsExist(metrics []string) error {
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/metrics",
		testutils.TraceeHostname,
		testutils.TraceePort,
	))
	if err != nil {
		fmt.Println("error making request:", err)
		return err
	}
	defer resp.Body.Close()

	// read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error reading response body:", err)
		return err
	}

	bodyStr := string(body)

	// check if all metrics exist
	for _, metric := range metrics {
		if strings.Contains(bodyStr, metric) {
			continue
		}
		return fmt.Errorf("metric %s not found", metric)
	}

	return nil
}

// checkIfPprofExist checks if all metrics exist in the metrics endpoint.
func checkIfPprofExist() error {
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/debug/pprof/",
		testutils.TraceeHostname,
		testutils.TraceePort,
	))
	if err != nil {
		fmt.Println("error making request:", err)
		return err
	}
	defer resp.Body.Close()

	// read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error reading response body:", err)
		return err
	}

	bodyStr := string(body)

	// check if pprof is enabled
	if strings.Contains(bodyStr, "Types of profiles available:") {
		return nil
	}

	return fmt.Errorf("pprof not enabled")
}

//
// Tests
//

// Note: Tests below need the following /etc/sudoers entry:
//
// ${USER} ALL=(ALL) NOPASSWD: ALL
//
// for the user running the tests.

// TestMetricsExist tests if the metrics endpoint returns all metrics.
func TestMetricsandPprofExist(t *testing.T) {
	t.Parallel()

	if !testutils.IsSudoCmdAvailableForThisUser() {
		t.Skip("skipping: sudo command is not available for this user")
	}

	cmd := "--output none --events=syslog --metrics --pprof"
	running := testutils.NewRunningTracee(context.Background(), cmd)

	// start tracee
	ready, runErr := running.Start()
	require.NoError(t, runErr)

	t.Cleanup(func() {
		runErr = running.Stop() // stop tracee
		require.NoError(t, runErr)
	})

	r := <-ready // block until tracee is ready (or not)
	switch r {
	case testutils.TraceeFailed:
		t.Fatal("tracee failed to start")
	case testutils.TraceeTimedout:
		t.Fatal("tracee timedout to start")
	case testutils.TraceeAlreadyRunning:
		t.Fatal("tracee is already running")
	}

	// do the test
	metricsErr := checkIfMetricsExist(metrics)
	pprofErr := checkIfPprofExist()

	// check if all metrics exist
	require.NoError(t, metricsErr)
	require.NoError(t, pprofErr)
}
