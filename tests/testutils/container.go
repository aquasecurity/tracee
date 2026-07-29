package testutils

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

var (
	containerEngineOnce sync.Once
	containerEnginePath string
)

// ContainerEngine returns the container engine CLI to use for integration tests, resolved
// once: the TRACEE_CONTAINER_ENGINE env override if set, otherwise the first of "docker" or
// "podman" found in PATH, otherwise "" when neither is available. podman's CLI is
// docker-compatible for the verbs the tests use (run/pull/rm/image pull), so either works.
func ContainerEngine() string {
	containerEngineOnce.Do(func() {
		if eng := os.Getenv("TRACEE_CONTAINER_ENGINE"); eng != "" {
			containerEnginePath = eng
			return
		}
		for _, eng := range []string{"docker", "podman"} {
			if _, err := exec.LookPath(eng); err == nil {
				containerEnginePath = eng
				return
			}
		}
	})
	return containerEnginePath
}

// RequireContainerEngine returns the container engine CLI, skipping the test when none is
// available (no docker/podman in PATH and no TRACEE_CONTAINER_ENGINE override).
func RequireContainerEngine(t *testing.T) string {
	t.Helper()
	engine := ContainerEngine()
	if engine == "" {
		t.Skip("no container engine available: install docker or podman, or set TRACEE_CONTAINER_ENGINE")
	}
	return engine
}

type socketCandidate struct {
	id   runtime.RuntimeId
	path string
}

// ContainerEngineSocket returns the tracee RuntimeId and rootful API socket path to use for
// enrichment tests (the engine's API socket service must be running). It prefers the socket
// matching the detected engine, then falls back to whichever known socket actually exists —
// this handles the podman-docker shim, where the CLI is "docker" but only podman's socket is
// running. tracee's Docker enricher serves podman too (its API is docker-compatible). Override
// with TRACEE_CONTAINER_SOCKET. Returns (Unknown, "") when no engine is available.
func ContainerEngineSocket() (runtime.RuntimeId, string) {
	if ContainerEngine() == "" {
		return runtime.Unknown, ""
	}
	if sock := os.Getenv("TRACEE_CONTAINER_SOCKET"); sock != "" {
		return socketRuntimeID(sock), sock
	}

	podman := socketCandidate{runtime.Podman, "/run/podman/podman.sock"}
	docker := socketCandidate{runtime.Docker, "/var/run/docker.sock"}

	order := []socketCandidate{docker, podman}
	if strings.Contains(ContainerEngine(), "podman") {
		order = []socketCandidate{podman, docker}
	}
	for _, c := range order {
		if socketExists(c.path) {
			return c.id, c.path
		}
	}
	return runtime.Unknown, "" // no running engine API socket found
}

// RequireContainerEngineSocket returns the runtime id and a RUNNING API socket path for the
// detected engine, skipping the test (with enable instructions) when none is found. Container
// enrichment needs the engine's API socket, which the engine CLI itself does not require.
func RequireContainerEngineSocket(t *testing.T) (runtime.RuntimeId, string) {
	t.Helper()
	id, sock := ContainerEngineSocket()
	if sock == "" {
		t.Skip("no running container-engine API socket found — container enrichment tests need it.\n" +
			"  enable one of:\n" +
			"    podman: sudo systemctl enable --now podman.socket   (creates /run/podman/podman.sock)\n" +
			"    docker: ensure the docker daemon is running          (/var/run/docker.sock)\n" +
			"  or set TRACEE_CONTAINER_SOCKET=/path/to/api.sock")
	}
	return id, sock
}

// socketExists reports whether path is an existing unix socket.
func socketExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// socketRuntimeID picks the tracee RuntimeId for an explicit socket override.
func socketRuntimeID(sock string) runtime.RuntimeId {
	if strings.Contains(sock, "podman") || strings.Contains(ContainerEngine(), "podman") {
		return runtime.Podman
	}
	return runtime.Docker
}
