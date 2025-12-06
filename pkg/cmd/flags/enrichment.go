package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

const (
	EnrichmentFlag = "enrichment"

	containerEnabledFlag          = "container.enabled"
	containerCgroupPathFlag       = "container.cgroup.path"
	containerCgroupForceFlag      = "container.cgroup.force"
	containerDockerSocketFlag     = "container.docker.socket"
	containerContainerdSocketFlag = "container.containerd.socket"
	containerCrioSocketFlag       = "container.crio.socket"
	containerPodmanSocketFlag     = "container.podman.socket"
	resolveFdFlag                 = "resolve-fd"
	execHashEnabledFlag           = "exec-hash.enabled"
	execHashModeFlag              = "exec-hash.mode"
	userStackTraceFlag            = "user-stack-trace"

	enrichInvalidFlagFormat = "invalid enrichment flag: %s, use 'tracee man enrichment' for more info"
)

// EnrichmentConfig is the configuration for enrichment
type EnrichmentConfig struct {
	Container ContainerEnrichmentConfig `mapstructure:"container"`
	// TODO: those are not used yet, it will come in a different PR,
	// as we will have to redo --output first (@josedonizetti)
	ResolveFd      bool           `mapstructure:"resolve-fd"`
	ExecHash       ExecHashConfig `mapstructure:"exec-hash"`
	UserStackTrace bool           `mapstructure:"user-stack-trace"`
}

// ContainerEnrichmentConfig is the container enrichment configuration
type ContainerEnrichmentConfig struct {
	Enabled          bool                  `mapstructure:"enabled"`
	Cgroup           ContainerCgroupConfig `mapstructure:"cgroup"`
	DockerSocket     string                `mapstructure:"docker-socket"`
	ContainerdSocket string                `mapstructure:"containerd-socket"`
	CrioSocket       string                `mapstructure:"crio-socket"`
	PodmanSocket     string                `mapstructure:"podman-socket"`
}

// ContainerCgroupConfig is the container cgroup configuration
type ContainerCgroupConfig struct {
	Path  string `mapstructure:"path"`
	Force bool   `mapstructure:"force"`
}

// ExecHashConfig is the exec hash configuration
type ExecHashConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Mode    string `mapstructure:"mode"`
}

// GetRuntimeSockets returns the runtime sockets for the enrichment configuration
func (e *EnrichmentConfig) GetRuntimeSockets() (runtime.Sockets, error) {
	sockets := runtime.Sockets{}
	if e.Container.DockerSocket != "" {
		err := sockets.Register(runtime.Docker, e.Container.DockerSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register docker socket: %v", err)
		}
	}
	if e.Container.ContainerdSocket != "" {
		err := sockets.Register(runtime.Containerd, e.Container.ContainerdSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register containerd socket: %v", err)
		}
	}
	if e.Container.CrioSocket != "" {
		err := sockets.Register(runtime.Crio, e.Container.CrioSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register crio socket: %v", err)
		}
	}
	if e.Container.PodmanSocket != "" {
		err := sockets.Register(runtime.Podman, e.Container.PodmanSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register podman socket: %v", err)
		}
	}
	return sockets, nil
}

// flags returns the flags for the enrichment configuration
func (e *EnrichmentConfig) flags() []string {
	flags := []string{}

	if e.Container.Enabled {
		flags = append(flags, "container.enabled")
	}
	if e.Container.Cgroup.Path != "" {
		flags = append(flags, fmt.Sprintf("container.cgroup.path=%s", e.Container.Cgroup.Path))
	}
	if e.Container.Cgroup.Force {
		flags = append(flags, "container.cgroup.force")
	}
	if e.Container.DockerSocket != "" {
		flags = append(flags, fmt.Sprintf("container.docker.socket=%s", e.Container.DockerSocket))
	}
	if e.Container.ContainerdSocket != "" {
		flags = append(flags, fmt.Sprintf("container.containerd.socket=%s", e.Container.ContainerdSocket))
	}
	if e.Container.CrioSocket != "" {
		flags = append(flags, fmt.Sprintf("container.crio.socket=%s", e.Container.CrioSocket))
	}
	if e.Container.PodmanSocket != "" {
		flags = append(flags, fmt.Sprintf("container.podman.socket=%s", e.Container.PodmanSocket))
	}
	if e.ResolveFd {
		flags = append(flags, "resolve-fd")
	}
	if e.ExecHash.Enabled {
		flags = append(flags, "exec-hash.enabled")
	}
	if e.ExecHash.Mode != "" {
		flags = append(flags, fmt.Sprintf("exec-hash.mode=%s", e.ExecHash.Mode))
	}
	if e.UserStackTrace {
		flags = append(flags, "user-stack-trace")
	}

	return flags
}

// PrepareEnrichment prepares the enrichment configuration from a list of flags
func PrepareEnrichment(enrichment []string) (EnrichmentConfig, error) {
	var enrichmentConfig EnrichmentConfig

	for _, flag := range enrichment {
		parts := strings.Split(flag, "=")
		if len(parts) != 2 && !isEnrichmentBoolFlag(parts[0]) {
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flag)
		}

		if len(parts) > 1 && isEnrichmentBoolFlag(parts[0]) {
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flag)
		}

		flagName := parts[0]

		switch flagName {
		case containerEnabledFlag:
			enrichmentConfig.Container.Enabled = true
		case containerCgroupPathFlag:
			enrichmentConfig.Container.Cgroup.Path = parts[1]
		case containerCgroupForceFlag:
			enrichmentConfig.Container.Cgroup.Force = true
		case containerDockerSocketFlag:
			enrichmentConfig.Container.DockerSocket = parts[1]
		case containerContainerdSocketFlag:
			enrichmentConfig.Container.ContainerdSocket = parts[1]
		case containerCrioSocketFlag:
			enrichmentConfig.Container.CrioSocket = parts[1]
		case containerPodmanSocketFlag:
			enrichmentConfig.Container.PodmanSocket = parts[1]
		case resolveFdFlag:
			enrichmentConfig.ResolveFd = true
		case execHashEnabledFlag:
			enrichmentConfig.ExecHash.Enabled = true
		case execHashModeFlag:
			enrichmentConfig.ExecHash.Mode = parts[1]
		case userStackTraceFlag:
			enrichmentConfig.UserStackTrace = true
		default:
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flagName)
		}
	}

	return enrichmentConfig, nil
}

// isEnrichmentBoolFlag checks if a flag is a boolean flag for enrichment
func isEnrichmentBoolFlag(flag string) bool {
	return flag == containerEnabledFlag ||
		flag == containerCgroupForceFlag ||
		flag == resolveFdFlag ||
		flag == execHashEnabledFlag ||
		flag == userStackTraceFlag
}

// invalidEnrichmentFlagError formats the error message for an invalid enrichment flag.
func invalidEnrichmentFlagError(flag string) string {
	return fmt.Sprintf(enrichInvalidFlagFormat, flag)
}
