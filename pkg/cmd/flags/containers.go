package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

const ContainersFlag = "containers"

func containersHelp() string {
	return `Configure container enrichment and runtime sockets for container events enrichment.

Flags:
  --containers enrich=<true/false>       Enable or disable container enrichment.
  --containers sockets.<runtime>=<path> Configure container runtime sockets for enrichment. Supported runtimes:
                                         - CRI-O      (crio, cri-o)
                                         - Containerd (containerd)
                                         - Docker     (docker)
                                         - Podman     (podman)
  --containers cgroupfs=<path>          Configure the path to the cgroupfs where container cgroups are created.

Examples:
  --containers enrich=true
  --containers sockets.docker=/var/run/docker.sock
  --containers cgroupfs=/sys/fs/cgroup
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

func parseContainerFlags(containerArgs []string) map[string]string {
	containerFlags := make(map[string]string)
	for _, arg := range containerArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			containerFlags[parts[0]] = parts[1]
		}
	}
	return containerFlags
}

func PrepareContainers(containerFlags []string) (runtime.Sockets, bool, string, error) {
	var noContainersEnrich bool
	var cgroupfsPath string
	supportedRuntimes := []string{"crio", "cri-o", "containerd", "docker", "podman"}
	sockets := runtime.Sockets{}
	anySocketRegistered := false

	flagMap := parseContainerFlags(containerFlags)

	for key, value := range flagMap {
		if key == "enrich" {
			if value == "false" {
				noContainersEnrich = true
			} else if value != "true" {
				return sockets, noContainersEnrich, cgroupfsPath, errfmt.Errorf("invalid value for enrich flag (must be true or false)")
			}
		} else if strings.HasPrefix(key, "sockets.") {
			runtimeName := strings.TrimPrefix(key, "sockets.")
			if !contains(supportedRuntimes, runtimeName) {
				return sockets, noContainersEnrich, cgroupfsPath, errfmt.Errorf("unsupported container runtime in sockets flag (see --containers help for supported runtimes)")
			}
			err := sockets.Register(runtime.FromString(runtimeName), value)
			if err != nil {
				return sockets, noContainersEnrich, cgroupfsPath, errfmt.Errorf("failed to register runtime socket, %s", err.Error())
			}
		} else if key == "cgroupfs" {
			cgroupfsPath = value
		} else {
			return sockets, noContainersEnrich, cgroupfsPath, errfmt.Errorf("unknown container flag: %s", key)
		}
	}

	if !anySocketRegistered {
		sockets = runtime.Autodiscover(func(err error, runtime runtime.RuntimeId, socket string) {
			if err != nil {
				logger.Debugw("RuntimeSockets: failed to register default", "socket", runtime.String(), "error", err)
			} else {
				logger.Debugw("RuntimeSockets: registered default", "socket", runtime.String(), "from", socket)
			}
		})
	}

	return sockets, noContainersEnrich, cgroupfsPath, nil
}
