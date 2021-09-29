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
	waitTime                   = 3
	traceeDockerRunBTFEnabled  = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -t aquasec/tracee:latest`
	traceeDockerRunBTFDisabled = `run --detach --name tracee --rm --pid=host --privileged -v /tmp/tracee:/tmp/tracee -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -it aquasec/tracee:latest`
)

func TestLaunchTracee(t *testing.T) {
	t.Run("BTF enabled", func(t *testing.T) {
		// launch tracee container
		fmt.Println("Launching Tracee container...")
		b, err := exec.Command("docker", strings.Split(traceeDockerRunBTFEnabled, " ")...).CombinedOutput()
		assert.NoError(t, err)
		containerID := strings.TrimSpace(string(b))
		fmt.Println("Tracee container ID: ", containerID)

		// wait for tracee to get ready
		time.Sleep(time.Second * waitTime)

		// do an `strace ls`
		fmt.Println("Running `strace ls`...")
		assert.NoError(t, exec.Command("strace", "ls").Run())

		// wait for tracee to detect
		time.Sleep(time.Second * waitTime)

		// get tracee container logs
		containerLogs, err := exec.Command("docker", "logs", containerID).CombinedOutput()

		// assert results
		fmt.Println("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		fmt.Println("Terminating the Tracee container...")
		assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
	})

	t.Run("BTF disabled", func(t *testing.T) {
		// launch tracee container
		fmt.Println("Launching Tracee container...")
		b, err := exec.Command("docker", strings.Split(traceeDockerRunBTFDisabled, " ")...).CombinedOutput()
		assert.NoError(t, err)
		containerID := strings.TrimSpace(string(b))
		fmt.Println("Tracee container ID: ", containerID)

		// wait for tracee to get ready
		time.Sleep(time.Second * waitTime)

		// do an `strace ls`
		fmt.Println("Running `strace ls`...")
		assert.NoError(t, exec.Command("strace", "ls").Run())

		// wait for tracee to detect
		time.Sleep(time.Second * waitTime)

		// get tracee container logs
		containerLogs, err := exec.Command("docker", "logs", containerID).CombinedOutput()

		// assert results
		fmt.Println("Asserting Logs...")
		assert.Contains(t, string(containerLogs), `Signature ID: TRC-2`)

		// kill the container
		fmt.Println("Terminating the Tracee container...")
		assert.NoError(t, exec.Command("docker", "kill", containerID).Run())
	})
}
