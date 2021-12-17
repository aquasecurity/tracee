package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

const (
	waitTime                   = time.Second * 3
	traceeDockerRunBTFEnabled  = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -t aquasec/tracee:latest`
	traceeDockerRunBTFDisabled = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -it aquasec/tracee:latest`
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

// TestLaunchTracee tests the basic sanity workflow of running tracee
// and detecting an attack by simulating a signature trigger
func TestLaunchTracee(t *testing.T) {
	t.Run("BTF enabled", func(t *testing.T) {
		containerID := launchTracee(t, traceeDockerRunBTFEnabled)

		// wait for tracee to get ready
		time.Sleep(waitTime)

		// do an `strace ls`
		_ = runCommand(t, "strace", "ls")

		// wait for tracee to detect
		time.Sleep(waitTime)

		// get tracee container logs
		containerLogs := runCommand(t, "docker", "logs", containerID)

		// assert results
		t.Log("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		t.Log("Terminating the Tracee container...")
		assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
	})

	t.Run("BTF disabled", func(t *testing.T) {
		containerID := launchTracee(t, traceeDockerRunBTFDisabled)

		// wait for tracee to get ready
		time.Sleep(waitTime)

		// do an `strace ls`
		_ = runCommand(t, "strace", "ls")

		// wait for tracee to detect
		time.Sleep(waitTime)

		// get tracee container logs
		containerLogs := runCommand(t, "docker", "logs", containerID)

		// assert results
		t.Log("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		t.Log("Terminating the Tracee container...")
		assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
	})
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

func setupTraceeContainer(ctx context.Context) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      "tracee",
		Privileged: true,
		BindMounts: map[string]string{"/tmp/tracee": "/tmp/tracee"},
		Name:       "tracee",
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

func setupTraceeTrainerContainer(ctx context.Context, sigid string) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      "tracee-trainer",
		Entrypoint: []string{"/runner", sigid},
		Privileged: true,
		Name:       "tracee-trainer",
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

func TestTraceeSignatures(t *testing.T) {
	for _, sigid := range []string{"TRC-11"} {
		t.Run(sigid, func(t *testing.T) {
			ctx := context.Background()

			// run tracee container
			traceeContainer, err := setupTraceeContainer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeContainer.Terminate(ctx)

			// wait for tracee to initialize
			time.Sleep(time.Second * 5)

			// run trace signature trainer container
			traceeSigTrainer, err := setupTraceeTrainerContainer(ctx, sigid)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeSigTrainer.Terminate(ctx)

			// wait for tracee to detect
			time.Sleep(time.Second * 10)

			b, err := traceeContainer.Logs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			log, err := ioutil.ReadAll(b)
			if err != nil {
				t.Fatal(err)
			}

			// assert our required signature was triggered
			assert.Contains(t, string(log), sigid)
		})
	}
}
