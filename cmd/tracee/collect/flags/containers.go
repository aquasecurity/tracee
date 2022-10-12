package flags

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/cmd/tracee/collect/internal/debug"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
)

func containersHelp() string {
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

func ParseContainers(containerFlags []string) (runtime.Sockets, error) {
	if checkCommandIsHelp(containerFlags) {
		fmt.Print(containersHelp())
		os.Exit(0)
	}

	if len(containerFlags) == 0 {
		return runtime.Autodiscover(func(err error, runtime runtime.RuntimeId, socket string) {
			if debug.Enabled() {
				if err != nil {
					fmt.Fprintf(os.Stderr, "RuntimeSockets: failed to register default %s socket:\n%v\n", runtime.String(), err)
				} else {
					fmt.Fprintf(os.Stdout, "RuntimeSockets: registered default %s runtime socket from %s\n", runtime.String(), socket)
				}
			}
		}), nil
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
		err := sockets.Register(runtime.FromString(containerRuntime), socket)

		if err != nil {
			return sockets, fmt.Errorf("failed to register runtime socket, %s", err.Error())
		}
	}

	return sockets, nil
}
