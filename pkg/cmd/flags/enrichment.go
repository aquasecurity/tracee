package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

const (
	EnrichmentFlag = "enrichment"

	containerFlag                 = "container"
	containerCgroupfsPathFlag     = "container.cgroupfs.path"
	containerCgroupfsForceFlag    = "container.cgroupfs.force"
	containerDockerSocketFlag     = "container.docker.socket"
	containerContainerdSocketFlag = "container.containerd.socket"
	containerCrioSocketFlag       = "container.crio.socket"
	containerPodmanSocketFlag     = "container.podman.socket"
	resolveFdFlag                 = "resolve-fd"
	execHashFlag                  = "exec-hash"
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
	Enabled          bool                    `mapstructure:"enabled"`
	Cgroupfs         ContainerCgroupfsConfig `mapstructure:"cgroupfs"`
	DockerSocket     string                  `mapstructure:"docker-socket"`
	ContainerdSocket string                  `mapstructure:"containerd-socket"`
	CrioSocket       string                  `mapstructure:"crio-socket"`
	PodmanSocket     string                  `mapstructure:"podman-socket"`
}

// ContainerCgroupfsConfig is the container cgroupfs configuration
type ContainerCgroupfsConfig struct {
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

	// Container: if Enabled is true OR any Container field is set, add container flag
	// Note: cgroupfs.force alone does not enable container, it requires cgroupfs.path
	if e.Container.Enabled || e.Container.Cgroupfs.Path != "" ||
		e.Container.DockerSocket != "" || e.Container.ContainerdSocket != "" ||
		e.Container.CrioSocket != "" || e.Container.PodmanSocket != "" {
		flags = append(flags, containerFlag)
	}
	if e.Container.Cgroupfs.Path != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", containerCgroupfsPathFlag, e.Container.Cgroupfs.Path))
	}
	// Only output cgroupfs.force if cgroupfs.path is also set
	if e.Container.Cgroupfs.Force && e.Container.Cgroupfs.Path != "" {
		flags = append(flags, containerCgroupfsForceFlag)
	}
	if e.Container.DockerSocket != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", containerDockerSocketFlag, e.Container.DockerSocket))
	}
	if e.Container.ContainerdSocket != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", containerContainerdSocketFlag, e.Container.ContainerdSocket))
	}
	if e.Container.CrioSocket != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", containerCrioSocketFlag, e.Container.CrioSocket))
	}
	if e.Container.PodmanSocket != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", containerPodmanSocketFlag, e.Container.PodmanSocket))
	}
	if e.ResolveFd {
		flags = append(flags, resolveFdFlag)
	}
	// ExecHash: if Enabled is true OR Mode is set, add exec-hash flag
	if e.ExecHash.Enabled || e.ExecHash.Mode != "" {
		flags = append(flags, execHashFlag)
	}
	if e.ExecHash.Mode != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", execHashModeFlag, e.ExecHash.Mode))
	}
	if e.UserStackTrace {
		flags = append(flags, userStackTraceFlag)
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
		case containerFlag:
			enrichmentConfig.Container.Enabled = true
		case containerCgroupfsPathFlag:
			enrichmentConfig.Container.Cgroupfs.Path = parts[1]
			enrichmentConfig.Container.Enabled = true // Setting cgroupfs.path enables container
		case containerCgroupfsForceFlag:
			enrichmentConfig.Container.Cgroupfs.Force = true
			// Note: cgroupfs.force alone does not enable container enrichment
		case containerDockerSocketFlag:
			enrichmentConfig.Container.DockerSocket = parts[1]
			enrichmentConfig.Container.Enabled = true // Setting docker.socket enables container
		case containerContainerdSocketFlag:
			enrichmentConfig.Container.ContainerdSocket = parts[1]
			enrichmentConfig.Container.Enabled = true // Setting containerd.socket enables container
		case containerCrioSocketFlag:
			enrichmentConfig.Container.CrioSocket = parts[1]
			enrichmentConfig.Container.Enabled = true // Setting crio.socket enables container
		case containerPodmanSocketFlag:
			enrichmentConfig.Container.PodmanSocket = parts[1]
			enrichmentConfig.Container.Enabled = true // Setting podman.socket enables container
		case resolveFdFlag:
			enrichmentConfig.ResolveFd = true
		case execHashFlag:
			enrichmentConfig.ExecHash.Enabled = true
		case execHashModeFlag:
			enrichmentConfig.ExecHash.Mode = parts[1]
			enrichmentConfig.ExecHash.Enabled = true // Setting exec-hash.mode enables exec-hash
		case userStackTraceFlag:
			enrichmentConfig.UserStackTrace = true
		default:
			return EnrichmentConfig{}, errfmt.Errorf(enrichInvalidFlagFormat, flagName)
		}
	}

	// Validate: cgroupfs.force requires cgroupfs.path
	if enrichmentConfig.Container.Cgroupfs.Force && enrichmentConfig.Container.Cgroupfs.Path == "" {
		return EnrichmentConfig{}, errfmt.Errorf("container.cgroupfs.force requires container.cgroupfs.path to be set")
	}

	return enrichmentConfig, nil
}

// isEnrichmentBoolFlag checks if a flag is a boolean flag for enrichment
func isEnrichmentBoolFlag(flag string) bool {
	return flag == containerFlag ||
		flag == containerCgroupfsForceFlag ||
		flag == resolveFdFlag ||
		flag == execHashFlag ||
		flag == userStackTraceFlag
}

// invalidEnrichmentFlagError formats the error message for an invalid enrichment flag.
func invalidEnrichmentFlagError(flag string) string {
	return fmt.Sprintf(enrichInvalidFlagFormat, flag)
}
