package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	waitTime                   = time.Second * 3
	traceeDockerRunWithWebhook = `run --detach --name tracee --rm --pid=host --net=host --privileged -v /tmp/tracee:/tmp/tracee -t aquasec/tracee:latest --webhook=%s --webhook-template=%s --webhook-content-type=application/json`
)

func launchTracee(t *testing.T, traceeCmd string) string {
	t.Helper()

	t.Log("Launching Tracee container...")
	b, err := exec.Command("docker", strings.Split(traceeCmd, " ")...).CombinedOutput()
	require.NoError(t, err)
	containerID := strings.TrimSpace(string(b))
	t.Log("Tracee container ID: ", containerID)
	return containerID
}

func runCommand(t *testing.T, cmd string, args ...string) string {
	t.Helper()

	t.Log("Running", cmd, args, "...")
	output, err := exec.Command(cmd, args...).CombinedOutput()
	assert.NoError(t, err)
	return string(output)
}

// TestWebhookIntegration tests the same workflow of running tracee
// and triggering a signature but also asserts the results of sending
// the payload to the HTTP webhook interface
func TestWebhookIntegration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Asserting Logs...")
		b, _ := ioutil.ReadAll(r.Body)
		assert.Contains(t, string(b), `"Properties":{"MITRE ATT\u0026CK":"Defense Evasion: Execution Guardrails","Severity":3}`)
		assert.Equal(t, "application/json", r.Header["Content-Type"][0])
	}))
	defer ts.Close()

	containerID := launchTracee(t, fmt.Sprintf(traceeDockerRunWithWebhook, ts.URL, "/tracee/templates/rawjson.tmpl"))

	// wait for tracee to get ready
	time.Sleep(waitTime)

	// do an `strace ls`
	_ = runCommand(t, "strace", "ls")

	// wait for tracee to detect
	time.Sleep(waitTime)

	// get tracee container logs
	containerLogs := runCommand(t, "docker", "logs", containerID)

	// assert results
	assert.NotContains(t, containerLogs, `error sending to webhook`)

	// kill the container
	t.Log("Terminating the Tracee container...")
	assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
}

type traceeContainer struct {
	testcontainers.Container
}

func runTraceeContainer(ctx context.Context, tempDir string) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      *traceeImageRef,
		Privileged: true,
		BindMounts: map[string]string{ // container:host
			tempDir:                tempDir,           // required for all
			"/etc/os-release-host": "/etc/os-release", // required for all
			"/usr/src":             "/usr/src",        // required for -nocore
			"/lib/modules":         "/lib/modules",    // required for -nocore
		},
		Env: map[string]string{
			"LIBBPFGO_OSRELEASE_FILE": "/etc/os-release-host",
		},
		Name:       "tracee",
		AutoRemove: true,
		WaitingFor: wait.NewLogStrategy("Loaded"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &traceeContainer{Container: container}, nil
}

func runTraceeTesterContainer(ctx context.Context, sigID string) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      *testerImageRef,
		Entrypoint: []string{"/entrypoint.sh", sigID},
		Privileged: true,
		Name:       "tracee-tester",
		AutoRemove: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &traceeContainer{Container: container}, nil
}

var (
	testerImageRef = flag.String("tracee-tester-image-ref", "docker.io/aquasec/tracee-tester:latest",
		"tracee tester container image reference")
	traceeImageRef = flag.String("tracee-image-ref", "tracee-nocore:latest",
		"tracee container image reference")
	signatureIDs = flag.String("tracee-signatures", "TRC-2,TRC-3,TRC-4,TRC-5,TRC-7,TRC-8,TRC-9,TRC-10,TRC-11,TRC-12,TRC-14",
		"comma-separated list of tracee signature identifiers")
)

func parseSignatureIDs() []string {
	signatureIDs := strings.Split(*signatureIDs, ",")
	for index, sigID := range signatureIDs {
		signatureIDs[index] = strings.TrimSpace(sigID)
	}
	return signatureIDs
}

// TestTraceeSignatures tests tracee signatures (-tracee-signatures) using the
// specified tracee container image (-tracee-image-ref) and tester container
// image (-tracee-tester-image-ref).
//
// Passing signature identifiers as input to the TestTraceeSignatures allows us
// to use it as a quick smoke test in the PR validation workflow or as
// full-blown end-to-end test run on CRON schedule.
//
// Passing tracee container image reference as input to the TestTraceeSignatures
// allows us to test different flavors of tracee container image, i.e. CO:RE
// non CO:RE, and CO:RE with BTFHub support.
//
//     go test -v -run "TestTraceeSignatures" ./tests/tracee_test.go \
//            -tracee-image-ref "tracee-nocore:latest" \
//            -tracee-tester-image-ref "aquasec/tracee-tester:latest" \
//            -tracee-signatures "TRC-2,TRC-3"
func TestTraceeSignatures(t *testing.T) {
	tempDir := os.TempDir()
	defer func() {
		os.RemoveAll(tempDir)
	}()

	for _, sigID := range parseSignatureIDs() {
		t.Run(fmt.Sprintf("%s/%s", *traceeImageRef, sigID), func(t *testing.T) {
			ctx := context.Background()

			traceeContainer, err := runTraceeContainer(ctx, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeContainer.Terminate(ctx)

			traceeTesterContainer, err := runTraceeTesterContainer(ctx, sigID)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeTesterContainer.Terminate(ctx)

			traceeContainer.assertLogs(t, ctx, sigID)
		})
	}
}

func (tc traceeContainer) assertLogs(t *testing.T, ctx context.Context, sigID string) {
	t.Helper()
	time.Sleep(time.Second * 10) // wait for tracee to detect

	b, err := tc.Logs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(log), fmt.Sprint("Signature ID: ", sigID))
}
