package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// fdPathTracee runs the binary in a separate process: capability management and
// SIGSTOP must not affect the test runner or its other integration tests.
func fdPathTracee(t *testing.T, events string) (process *exec.Cmd, outputFile, logFile string) {
	t.Helper()
	testutils.AssureIsRoot(t)
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "events.json")
	logPath := filepath.Join(dir, "tracee.log")
	output, err := os.Create(outputPath)
	require.NoError(t, err)
	log, err := os.Create(logPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, testutils.TraceeBinary,
		"--events", events, "--scope", fmt.Sprintf("pid=%d", os.Getpid()),
		"--enrichment", "fd-paths", "--capabilities", "bypass=false",
		"--output", "json", "--artifacts", "dir.path="+filepath.Join(dir, "artifacts"),
		"--server", "healthz", "--server", fmt.Sprintf("http-address=:%d", testutils.TraceePort))
	cmd.Stdout, cmd.Stderr = output, log
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cancel()
			<-done
		}
		cancel()
		_ = output.Close()
		_ = log.Close()
		if t.Failed() {
			contents, _ := os.ReadFile(logPath)
			t.Logf("tracee log:\n%s", contents)
		}
	})
	client := &http.Client{Timeout: time.Second}
	require.Eventually(t, func() bool {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", testutils.TraceePort))
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	}, 20*time.Second, 100*time.Millisecond, "tracee did not become ready")
	return cmd, outputPath, logPath
}

func fdPathEvents(outputPath string) []*pb.Event {
	output, err := os.ReadFile(outputPath)
	if err != nil {
		return nil
	}
	var events []*pb.Event
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		event := new(pb.Event)
		if protojson.Unmarshal(line, event) == nil {
			events = append(events, event)
		}
	}
	return events
}

func Test_FdPathsSurviveUserspaceBacklog(t *testing.T) {
	testutils.AssureIsRoot(t)
	file, err := os.CreateTemp("/tmp", "tracee-fd-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close(); _ = os.Remove(file.Name()) })
	cmd, output, _ := fdPathTracee(t, "close")
	require.NoError(t, cmd.Process.Signal(syscall.SIGSTOP))
	require.Eventually(t, func() bool {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		return err == nil && strings.Contains(string(status), "State:\tT")
	}, time.Second, 10*time.Millisecond, "tracee did not stop")

	// More than the old map's 1,024 slots, but comfortably within the perf
	// buffers. BPF keeps running while userspace cannot consume any entries.
	const count = 2048
	for i := 0; i < count; i++ {
		fd, err := syscall.Dup(int(file.Fd()))
		require.NoError(t, err)
		require.NoError(t, syscall.Close(fd))
	}
	require.NoError(t, cmd.Process.Signal(syscall.SIGCONT))
	require.Eventually(t, func() bool {
		matched := 0
		for _, event := range fdPathEvents(output) {
			if event.Name != "close" {
				continue
			}
			for _, field := range event.Data {
				if field.Name == "fd" && strings.HasSuffix(field.GetStr(), "="+file.Name()) {
					matched++
				}
			}
		}
		return matched == count
	}, 10*time.Second, 100*time.Millisecond, "queued close events lost their entry-time paths")
}
