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
  --containers cgroupfs.path=<path>     Configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection.
  --containers cgroupfs.force=true      Force the usage of the provided mountpoint path and skip auto-detection (only applies if cgroupfs.path is provided).

Examples:
  --containers enrich=true
  --containers sockets.docker=/var/run/docker.sock
  --containers cgroupfs.path=/sys/fs/cgroup
  --containers cgroupfs.force=true
`
}

type CgroupFlagsResult struct {
	NoEnrich      bool
	Sockets       runtime.Sockets
	CgroupfsPath  string
	CgroupfsForce bool
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

func PrepareContainers(containerFlags []string) (CgroupFlagsResult, error) {
	var noContainersEnrich bool
	var cgroupfsPath string
	var cgroupfsForce bool

	supportedRuntimes := []string{"crio", "cri-o", "containerd", "docker", "podman"}
	sockets := runtime.Sockets{}
	anySocketRegistered := false

	flagMap := parseContainerFlags(containerFlags)

	for key, value := range flagMap {
		if key == "enrich" {
			if value == "false" {
				noContainersEnrich = true
			} else if value != "true" {
				return CgroupFlagsResult{}, errfmt.Errorf("invalid value for enrich flag (must be true or false)")
			}
		} else if strings.HasPrefix(key, "sockets.") {
			runtimeName := strings.TrimPrefix(key, "sockets.")
			if !contains(supportedRuntimes, runtimeName) {
				return CgroupFlagsResult{}, errfmt.Errorf("unsupported container runtime in sockets flag (see --containers help for supported runtimes)")
			}
			err := sockets.Register(runtime.FromString(runtimeName), value)
			if err != nil {
				return CgroupFlagsResult{}, errfmt.Errorf("failed to register runtime socket, %s", err.Error())
			}
		} else if strings.HasPrefix(key, "cgroupfs.") {
			if key == "cgroupfs.path" {
				cgroupfsPath = value
			} else if key == "cgroupfs.force" {
				cgroupfsForce = value == "true"
			}
		} else {
			return CgroupFlagsResult{}, errfmt.Errorf("unknown container flag: %s", key)
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

	return CgroupFlagsResult{
		NoEnrich:      noContainersEnrich,
		Sockets:       sockets,
		CgroupfsPath:  cgroupfsPath,
		CgroupfsForce: cgroupfsForce,
	}, nil
}
