package flags

import (
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

const (
	EnrichFlag                    = "enrich"
	ContainerEnabledFlag          = "container.enabled"
	ContainerCgroupPathFlag       = "container.cgroup.path"
	ContainerDockerSocketFlag     = "container.docker.socket"
	ContainerContainerdSocketFlag = "container.containerd.socket"
	ContainerCrioSocketFlag       = "container.crio.socket"
	ContainerPodmanSocketFlag     = "container.podman.socket"
	ResolveFdFlag                 = "resolve-fd"
	ExecHashEnabledFlag           = "exec-hash.enabled"
	ExecHashModeFlag              = "exec-hash.mode"
	UserStackTraceFlag            = "user-stack-trace"

	enrichInvalidFlagFormat = "invalid enrichment flag: %s, use 'trace man enrichment' for more info"
)

func enrichmentHelp() string {
	return `Configure enrichment for container events.

Flags:
  --enrich container.enabled=<true/false>       Enable or disable container enrichment.
  --enrich container.cgroup.path=             Configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection.
  --enrich container.docker.socket=<socket_path> Configure the path to the docker socket.
  --enrich container.containerd.socket=<socket_path> Configure the path to the containerd socket.
  --enrich container.crio.socket=<socket_path> Configure the path to the crio socket.
  --enrich container.podman.socket=<socket_path> Configure the path to the podman socket.
  --enrich resolve-fd=<true/false>             Enable or disable resolve-fd.
  --enrich exec-hash.enabled=<true/false>     Enable or disable exec-hash.
  --enrich exec-hash.mode=                    Configure the mode for exec-hash.
  --enrich user-stack-trace=<true/false>      Enable or disable user-stack-trace.
`
}

type EnrichmentConfig struct {
	ContainerEnabled          bool
	ContainerCgroupPath       string
	ContainerDockerSocket     string
	ContainerContainerdSocket string
	ContainerCrioSocket       string
	ContainerPodmanSocket     string
	ResolveFd                 bool
	ExecHashEnabled           bool
	ExecHashMode              string
	UserStackTrace            bool
}

func PrepareEnrichment(enrichment []string) (EnrichmentConfig, error) {
	var enrichmentConfig EnrichmentConfig

	for _, flag := range enrichment {
		parts := strings.Split(flag, "=")
		if len(parts) != 2 && !IsBoolFlag(parts[0]) {
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flag)
		}

		if len(parts) > 1 && IsBoolFlag(parts[0]) {
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flag)
		}

		flagName := parts[0]

		switch flagName {
		case ContainerEnabledFlag:
			enrichmentConfig.ContainerEnabled = true
		case ContainerCgroupPathFlag:
			enrichmentConfig.ContainerCgroupPath = parts[1]
		case ContainerDockerSocketFlag:
			enrichmentConfig.ContainerDockerSocket = parts[1]
		case ContainerContainerdSocketFlag:
			enrichmentConfig.ContainerContainerdSocket = parts[1]
		case ContainerCrioSocketFlag:
			enrichmentConfig.ContainerCrioSocket = parts[1]
		case ContainerPodmanSocketFlag:
			enrichmentConfig.ContainerPodmanSocket = parts[1]
		case ResolveFdFlag:
			enrichmentConfig.ResolveFd = true
		case ExecHashEnabledFlag:
			enrichmentConfig.ExecHashEnabled = true
		case ExecHashModeFlag:
			enrichmentConfig.ExecHashMode = parts[1]
		case UserStackTraceFlag:
			enrichmentConfig.UserStackTrace = true
		default:
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flagName)
		}
	}

	return enrichmentConfig, nil
}

func IsBoolFlag(flag string) bool {
	return flag == "container.enabled" || flag == "resolve-fd" || flag == "exec-hash.enabled" || flag == "user-stack-trace"
}

func (e *EnrichmentConfig) GetRuntimeSockets() (runtime.Sockets, error) {
	sockets := runtime.Sockets{}
	if e.ContainerDockerSocket != "" {
		err := sockets.Register(runtime.Docker, e.ContainerDockerSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register docker socket: %v", err)
		}
	}
	if e.ContainerContainerdSocket != "" {
		err := sockets.Register(runtime.Containerd, e.ContainerContainerdSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register containerd socket: %v", err)
		}
	}
	if e.ContainerCrioSocket != "" {
		err := sockets.Register(runtime.Crio, e.ContainerCrioSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register crio socket: %v", err)
		}
	}
	if e.ContainerPodmanSocket != "" {
		err := sockets.Register(runtime.Podman, e.ContainerPodmanSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register podman socket: %v", err)
		}
	}
	return sockets, nil
}
