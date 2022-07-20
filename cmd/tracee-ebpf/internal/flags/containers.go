package flags

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/debug"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
)

func ContainersHelp() string {
	return `Select which container runtimes to connect to for container events enrichment.
By default, if no flag is passed, tracee will automatically detect installed runtimes by going through known runtime socket paths.

Tracee will look for the following paths:
1. Docker:     /var/run/docker.sock
2. Containerd: /var/run/containerd/containerd.sock
3. CRI-O:      /var/run/crio/crio.sock

If runtimes are specified, only the ones passed through flags will be connected to through the provided socket file path.
Supported runtimes are:

1. CRI-O      (crio, cri-o)
2. Containerd (containerd)
3. Docker     (docker)

Example:
  --crs crio:/var/run/crio/crio.sock
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
		return autoDiscoverSockets(), nil
	}

	supportedRuntimes := []string{"crio", "cri-o", "containerd", "docker"}

	sockets := runtime.Sockets{}

	for _, flag := range containerFlags {
		parts := strings.Split(flag, ":")
		if len(parts) != 2 {
			return sockets, fmt.Errorf("failed to parse container flags (must be of format {runtime}:{socket path})")
		}
		containerRuntime := parts[0]

		if !contains(supportedRuntimes, containerRuntime) {
			return sockets, fmt.Errorf("provided unsupported container runtime (see --crs help for supported runtimes)")
		}

		socket := parts[1]
		err := sockets.Register(runtimeStringToRuntimeId(containerRuntime), socket)

		if err != nil {
			return sockets, fmt.Errorf("failed to register runtime socket, %s", err.Error())
		}
	}

	return sockets, nil
}

//check default paths for all supported container runtimes and aggregate them
func autoDiscoverSockets() runtime.Sockets {
	sockets := runtime.Sockets{}
	const (
		defaultContainerd = "/var/run/containerd/containerd.sock"
		defaultDocker     = "/var/run/docker.sock"
		defaultCrio       = "/var/run/crio/crio.sock"
		defaultPodman     = "/var/run/podman/podman.sock"
	)

	registerSocket(&sockets, "containerd", defaultContainerd)
	registerSocket(&sockets, "docker", defaultDocker)
	registerSocket(&sockets, "crio", defaultCrio)
	registerSocket(&sockets, "podman", defaultPodman)

	return sockets
}

func registerSocket(sockets *runtime.Sockets, runtime string, socket string) {
	err := sockets.Register(runtimeStringToRuntimeId(runtime), socket)
	if debug.Enabled() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "RuntimeSockets: failed to register default %s socket:\n%v\n", runtime, err)
		} else {
			fmt.Fprintf(os.Stdout, "RuntimeSockets: registered default %s runtime socket from %s\n", runtime, socket)
		}
	}
}

func runtimeStringToRuntimeId(containerRuntime string) runtime.RuntimeId {
	switch containerRuntime {
	case "docker":
		return runtime.Docker
	case "crio":
		return runtime.Crio
	case "cri-o":
		return runtime.Crio
	case "podman":
		return runtime.Podman
	case "containerd":
		return runtime.Containerd
	default:
		return runtime.Unknown
	}
}
