package integration

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// resolveContainerdSocket returns the containerd socket the enricher test should
// use. It honors TRACEE_TEST_CONTAINERD_SOCKET, otherwise probes the common
// paths - the system socket (used by Docker's own containerd on a standard
// docker-ce install) first, then Docker's private containerd socket. It returns
// "" when none is found, in which case the test skips.
func resolveContainerdSocket() string {
	if s := os.Getenv("TRACEE_TEST_CONTAINERD_SOCKET"); s != "" {
		return s
	}
	for _, p := range []string{
		"/run/containerd/containerd.sock",
		"/var/run/docker/containerd/containerd.sock",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Test_ContainerdEnricher_Get verifies that the containerd runtime enricher
// (pkg/datastores/container/runtime/containerd.go) resolves image and pod
// metadata for a real containerd container.
//
// It drives the enricher directly, without the eBPF pipeline, so it is a
// focused regression guard for the containerd v2 client migration: it exercises
// the exact client API surface the enricher uses — NamespaceService().List,
// ContainerService().Get and ImageService().Get — against a live daemon.
//
// It reuses the containerd instance Docker already runs (no separate daemon is
// started, so there is no conflict with Docker) and operates only in a
// dedicated namespace, isolated from Docker's own "moby" namespace. The
// fixture is created with `ctr` because the container metadata store rejects
// records with a nil Spec; ctr builds a fully valid container, avoiding a
// brittle hand-marshaled OCI spec. The test skips when its prerequisites
// (root, a containerd socket, the ctr binary) are absent.
func Test_ContainerdEnricher_Get(t *testing.T) {
	testutils.AssureIsRoot(t)

	containerdSocket := resolveContainerdSocket()
	if containerdSocket == "" {
		t.Skip("no containerd socket found (set TRACEE_TEST_CONTAINERD_SOCKET); skipping containerd enricher test")
	}
	ctrBin, err := exec.LookPath("ctr")
	if err != nil {
		t.Skip("ctr binary not found in PATH; skipping containerd enricher test")
	}

	const (
		ns          = "tracee-enricher-it"
		containerID = "tracee-enricher-it-ctr"

		podName = "tracee-enricher-pod"
		podNS   = "tracee-enricher-ns"
		podUID  = "tracee-enricher-uid"
		contNm  = "tracee-enricher-cont"
	)
	image := busyboxImage

	// ctr runs a `ctr --address <socket> -n <ns> ...` command and returns its
	// combined output. --address must target the same socket the enricher uses,
	// otherwise the fixture would land on a different containerd daemon.
	ctr := func(args ...string) (string, error) {
		full := append([]string{"--address", containerdSocket, "-n", ns}, args...)
		out, err := exec.Command(ctrBin, full...).CombinedOutput()
		return string(out), err
	}

	// Best-effort cleanup of leftovers from a previous failed run, and at the end.
	cleanup := func() {
		_, _ = ctr("containers", "delete", containerID)
		_, _ = ctr("images", "remove", image)
		_ = exec.Command(ctrBin, "--address", containerdSocket, "namespaces", "remove", ns).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	// Pull the image into the test namespace (unpacks for the host platform).
	// A pull failure means the environment can't reach the registry or lacks a
	// working snapshotter, which is not a regression in the code under test.
	if out, err := ctr("images", "pull", image); err != nil {
		t.Skipf("failed to pull %s into containerd namespace %s (environment issue): %v\n%s",
			image, ns, err, out)
	}

	// Create the container metadata record (no task needed - the enricher only
	// reads metadata) referencing the pulled image.
	if out, err := ctr("containers", "create", image, containerID); err != nil {
		require.NoErrorf(t, err, "ctr containers create failed: %s", out)
	}

	// Attach CRI/k8s-style labels so the enricher's pod-metadata mapping is exercised.
	labelArgs := []string{"containers", "label", containerID,
		runtime.PodNameLabel + "=" + podName,
		runtime.PodNamespaceLabel + "=" + podNS,
		runtime.PodUIDLabel + "=" + podUID,
		runtime.ContainerNameLabel + "=" + contNm,
		runtime.ContainerTypeContainerdLabel + "=container",
	}
	if out, err := ctr(labelArgs...); err != nil {
		require.NoErrorf(t, err, "ctr containers label failed: %s", out)
	}

	// Build the enricher against the system socket and query the container.
	enricher, err := runtime.ContainerdEnricher(containerdSocket)
	require.NoError(t, err, "failed to create containerd enricher")
	defer func() {
		if err := enricher.Close(); err != nil {
			t.Logf("error closing enricher: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := enricher.Get(ctx, containerID)
	require.NoErrorf(t, err, "enricher.Get failed for container %s", containerID)

	// Image name and digest are resolved from the containerd image store.
	assert.Contains(t, result.Image, "busybox", "enriched image name should reference the pulled image")
	assert.NotEmpty(t, result.ImageDigest, "enriched image digest should not be empty")

	// Pod metadata is mapped from the CRI labels.
	assert.Equal(t, podName, result.PodName, "pod name should be mapped from labels")
	assert.Equal(t, podNS, result.Namespace, "pod namespace should be mapped from labels")
	assert.Equal(t, podUID, result.UID, "pod uid should be mapped from labels")
	assert.Equal(t, contNm, result.ContName, "container name should be mapped from labels")
	assert.False(t, result.Sandbox, "container should not be flagged as sandbox")
}
