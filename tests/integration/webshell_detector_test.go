package integration

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Level 1 (base): a shell/tool exec identified by its path (kernel-filterable data field).
// Format args: produced-event name, shell path.
const webshellL1YAML = `type: detector
id: webshell-test-l1
produced_event:
  name: %s
  version: 1.0.0
  description: test - a shell or tool was executed
  tags:
    - test
  fields:
    - name: binary_path
      type: string
    - name: uid
      type: uint32
requirements:
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=%s
auto_populate:
  detected_from: true
output:
  fields:
    - name: binary_path
      expression: getEventData("pathname")
    - name: uid
      expression: workload.process.real_user.id
`

// Level 2 (composed): keep only executions performed by a service account. Its scope_filter is threaded
// down the chain onto sched_process_exec. Format args: produced-event name, input-event name, uid.
const webshellL2YAML = `type: detector
id: webshell-test-l2
produced_event:
  name: %s
  version: 1.0.0
  description: test - tool executed under a service account
  tags:
    - test
  fields:
    - name: uid
      type: uint32
requirements:
  events:
    - name: %s
      dependency: required
      scope_filters:
        - uid=%d
threat:
  name: Web Shell Command Execution
  severity: high
  description: A shell or network tool was executed under a service account
  mitre:
    technique:
      id: T1505.003
      name: Web Shell
    tactic:
      name: Persistence
auto_populate:
  threat: true
  detected_from: true
output:
  fields:
    - name: uid
      expression: workload.process.real_user.id
`

// Test_YAMLDetectorWebshellChain is a real-technique end-to-end for the matched-rules + detector-filter
// features: a two-level detector chain (MITRE T1505.003, Web Shell) where the base detector selects a
// shell exec by path (kernel data filter) and the composed detector keeps only executions by a service
// account (scope filter threaded down the chain). It proves the chain fires end-to-end on a real exec and
// that the composed detector's scope filter is applied through the chain - the same shell run as root
// produces the base finding but NOT the web-shell threat.
func Test_YAMLDetectorWebshellChain(t *testing.T) {
	testutils.AssureIsRoot(t)
	defer goleak.VerifyNone(t)

	const serviceUID = 65534 // nobody: a stand-in for a web-service account (www-data, nginx, ...)
	const l1Event = "test_interactive_tool_exec"
	const l2Event = "test_webshell_indicator"

	// Resolve /bin/sh to the path sched_process_exec will actually report (distros symlink it differently).
	shell, err := filepath.EvalSymlinks("/bin/sh")
	require.NoError(t, err, "failed to resolve /bin/sh")

	yamlDir := t.TempDir()
	createTempYAMLDetector(t, yamlDir, "webshell_l1.yaml", fmt.Sprintf(webshellL1YAML, l1Event, shell))
	createTempYAMLDetector(t, yamlDir, "webshell_l2.yaml", fmt.Sprintf(webshellL2YAML, l2Event, l1Event, serviceUID))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trc, buf, stream := startTraceeWithYAMLDetectors(ctx, t, yamlDir)
	defer func() {
		trc.Unsubscribe(stream)
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Logf("Error stopping Tracee: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)
	buf.Clear()

	runShell := func(uid uint32) {
		cmd := exec.Command(shell, "-c", "exit 0")
		if uid != 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		}
		_ = cmd.Run()
	}

	// Interleave a service-account run (the malicious pattern) with a root run (benign) several times.
	for i := 0; i < 5; i++ {
		runShell(0)          // root: base detector fires, web-shell threat must NOT
		runShell(serviceUID) // service account: both must fire
	}

	// Wait for the composed web-shell finding attributed to the service account.
	deadline := time.Now().Add(15 * time.Second)
	for !detectorEventForUID(buf, l2Event, serviceUID) && time.Now().Before(deadline) {
		runShell(serviceUID)
		time.Sleep(300 * time.Millisecond)
	}

	// Base detector fires on the shell exec regardless of uid - its data.pathname filter selects the
	// tool, not the user.
	require.True(t, detectorEventForUID(buf, l1Event, serviceUID),
		"base detector must fire for the service-account shell exec")
	require.True(t, detectorEventForUID(buf, l1Event, 0),
		"base detector must fire for the root shell exec too (data filter is path-based)")

	// Composed detector fires ONLY for the service account: its scope_filter uid=service is applied
	// through the chain, so a root exec of the same shell does not produce the web-shell threat.
	require.True(t, detectorEventForUID(buf, l2Event, serviceUID),
		"web-shell threat must fire for the service-account exec")
	require.False(t, detectorEventForUID(buf, l2Event, 0),
		"web-shell threat must NOT fire for the root exec (uid scope filtered the chain)")
}

// detectorEventForUID reports whether the buffer holds an event of the given name whose workload real
// user id matches uid.
func detectorEventForUID(buf *testutils.EventBuffer, eventName string, uid uint32) bool {
	for _, e := range buf.GetCopy() {
		if e == nil || e.Name != eventName ||
			e.Workload == nil || e.Workload.Process == nil ||
			e.Workload.Process.RealUser == nil || e.Workload.Process.RealUser.Id == nil {
			continue
		}
		if uint32(e.Workload.Process.RealUser.Id.Value) == uid {
			return true
		}
	}
	return false
}
