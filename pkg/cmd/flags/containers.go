package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func containersHelp() string {
	return `Select which container runtimes to connect to for container events enrichment.
By default, if no flag is passed, tracee will automatically detect installed runtimes by going through known runtime socket paths.

Tracee will look for the following paths:
1. Docker:     /var/run/docker.sock
2. Containerd: /var/run/containerd/containerd.sock
3. CRI-O:      /var/run/crio/crio.sock
4. Podman:     /var/run/podman/podman.sock

If runtimes are specified, only the ones passed through flags will be connected to through the provided socket file path.
Supported runtimes are:

1. CRI-O      (crio, cri-o)
2. Containerd (containerd)
3. Docker     (docker)
4. Podman     (podman)

Example:
  --cri crio:/var/run/crio/crio.sock
`
}

func contains(s []string, val string) bool {
	for _, str := range s {
		if str == val {
			return true
		}
	}
	return false
}

func PrepareContainers(containerFlags []string) (runtime.Sockets, error) {
	if len(containerFlags) == 0 {
		return runtime.Autodiscover(func(err error, runtime runtime.RuntimeId, socket string) {
			if err != nil {
				logger.Debugw("RuntimeSockets: failed to register default", "socket", runtime.String(), "error", err)
			} else {
				logger.Debugw("RuntimeSockets: registered default", "socket", runtime.String(), "from", socket)
			}
		}), nil
	}

	supportedRuntimes := []string{"crio", "cri-o", "containerd", "docker", "podman"}

	sockets := runtime.Sockets{}

	for _, flag := range containerFlags {
		parts := strings.Split(flag, ":")
		if len(parts) != 2 {
			return sockets, errfmt.Errorf("failed to parse container flags (must be of format {runtime}:{socket path})")
		}
		containerRuntime := parts[0]

		if !contains(supportedRuntimes, containerRuntime) {
			return sockets, errfmt.Errorf("provided unsupported container runtime (see --cri help for supported runtimes)")
		}

		socket := parts[1]
		err := sockets.Register(runtime.FromString(containerRuntime), socket)

		if err != nil {
			return sockets, errfmt.Errorf("failed to register runtime socket, %s", err.Error())
		}
	}

	return sockets, nil
}
