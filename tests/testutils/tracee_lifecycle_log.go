package testutils

import "testing"

// LogTraceeStarted / LogTraceeStopped emit the STANDARD tracee lifecycle markers used across the
// integration suite, so a run shows every test's tracee start/stop in one consistent format
// (previously split between "=== tracee STARTED: name ===" and "--- started tracee ---"). The
// test name makes each marker attributable when many tests interleave. Use these instead of
// ad-hoc t.Log strings.
func LogTraceeStarted(t testing.TB) {
	t.Helper()
	t.Logf("=== tracee STARTED: %s ===", t.Name())
}

func LogTraceeStopped(t testing.TB) {
	t.Helper()
	t.Logf("=== tracee STOPPED: %s ===", t.Name())
}
