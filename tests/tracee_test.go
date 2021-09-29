package tests

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	waitTime                   = time.Second * 3
	traceeDockerRunBTFEnabled  = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -t aquasec/tracee:latest`
	traceeDockerRunBTFDisabled = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -it aquasec/tracee:latest`
)

func launchTracee(t *testing.T, traceeCmd string) string {
	t.Helper()

	fmt.Println("Launching Tracee container...")
	b, err := exec.Command("docker", strings.Split(traceeCmd, " ")...).CombinedOutput()
	assert.NoError(t, err)
	containerID := strings.TrimSpace(string(b))
	fmt.Println("Tracee container ID: ", containerID)
	return containerID
}

func runCommand(t *testing.T, cmd string, args ...string) string {
	t.Helper()

	fmt.Println("Running", cmd, args, "...")
	output, err := exec.Command(cmd, args...).CombinedOutput()
	assert.NoError(t, err)
	return string(output)
}

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
		fmt.Println("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		fmt.Println("Terminating the Tracee container...")
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
		fmt.Println("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		fmt.Println("Terminating the Tracee container...")
		assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
	})
}
