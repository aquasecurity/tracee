package flags

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
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
	fdPathsFlag                   = "fd-paths"
	executableHashFlag            = "executable-hash"
	executableHashModeFlag        = "executable-hash.mode"
	userStackFlag                 = "user-stack"
	environmentFlag               = "environment"
	decodedDataFlag               = "decoded-data"

	// environmentFlag and decodedDataFlag are shared between output and enrichment
	enrichInvalidFlagFormat = "invalid enrichment flag: %s, use 'tracee man enrichment' for more info"
)

// EnrichmentConfig is the configuration for enrichment
type EnrichmentConfig struct {
	Container      ContainerEnrichmentConfig `mapstructure:"container"`
	FdPaths        bool                      `mapstructure:"fd-paths"`
	Environment    bool                      `mapstructure:"environment"`
	ExecutableHash ExecutableHashConfig      `mapstructure:"executable-hash"`
	UserStack      bool                      `mapstructure:"user-stack"`
	DecodedData    bool                      `mapstructure:"decoded-data"`
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

// ExecutableHashConfig is the executable hash configuration
type ExecutableHashConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Mode    string `mapstructure:"mode"`
}

// GetRuntimeSockets returns the runtime sockets for the enrichment configuration
func (e *EnrichmentConfig) GetRuntimeSockets() (runtime.Sockets, error) {
	sockets := runtime.Sockets{}
	anySocketRegistered := false

	if e.Container.DockerSocket != "" {
		err := sockets.Register(runtime.Docker, e.Container.DockerSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register docker socket: %v", err)
		}
		anySocketRegistered = true
	}
	if e.Container.ContainerdSocket != "" {
		err := sockets.Register(runtime.Containerd, e.Container.ContainerdSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register containerd socket: %v", err)
		}
		anySocketRegistered = true
	}
	if e.Container.CrioSocket != "" {
		err := sockets.Register(runtime.Crio, e.Container.CrioSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register crio socket: %v", err)
		}
		anySocketRegistered = true
	}
	if e.Container.PodmanSocket != "" {
		err := sockets.Register(runtime.Podman, e.Container.PodmanSocket)
		if err != nil {
			return sockets, errfmt.Errorf("failed to register podman socket: %v", err)
		}
		anySocketRegistered = true
	}

	// If no sockets were explicitly configured, auto-discover default socket paths
	if !anySocketRegistered {
		sockets = runtime.Autodiscover(func(err error, rtime runtime.RuntimeId, socket string) {
			logger.Debugw("RuntimeSockets: failed to register default", "runtime", rtime.String(), "socket", socket, "error", err)
		})

		// Log successfully registered sockets
		for _, rtime := range []runtime.RuntimeId{runtime.Docker, runtime.Containerd, runtime.Crio, runtime.Podman} {
			if sockets.Supports(rtime) {
				logger.Debugw("RuntimeSockets: registered default", "runtime", rtime.String(), "socket", sockets.Socket(rtime))
			}
		}
	}

	return sockets, nil
}

// GetCalcHashesOption converts ExecutableHashConfig to digest.CalcHashesOption
func (e *EnrichmentConfig) GetCalcHashesOption() digest.CalcHashesOption {
	if !e.ExecutableHash.Enabled && e.ExecutableHash.Mode == "" {
		return digest.CalcHashesNone
	}

	// If mode is set, use it; otherwise default to dev-inode
	mode := e.ExecutableHash.Mode
	if mode == "" {
		mode = "dev-inode"
	}

	switch mode {
	case "none":
		return digest.CalcHashesNone
	case "inode":
		return digest.CalcHashesInode
	case "dev-inode":
		return digest.CalcHashesDevInode
	case "digest-inode":
		return digest.CalcHashesDigestInode
	default:
		// Default to dev-inode if invalid mode
		return digest.CalcHashesDevInode
	}
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
	if e.FdPaths {
		flags = append(flags, fdPathsFlag)
	}
	if e.Environment {
		flags = append(flags, environmentFlag)
	}
	// ExecutableHash: if Enabled is true OR Mode is set, add executable-hash flag
	if e.ExecutableHash.Enabled || e.ExecutableHash.Mode != "" {
		flags = append(flags, executableHashFlag)
	}
	if e.ExecutableHash.Mode != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", executableHashModeFlag, e.ExecutableHash.Mode))
	}
	if e.UserStack {
		flags = append(flags, userStackFlag)
	}
	if e.DecodedData {
		flags = append(flags, decodedDataFlag)
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
		case fdPathsFlag:
			enrichmentConfig.FdPaths = true
		case environmentFlag:
			enrichmentConfig.Environment = true
		case executableHashFlag:
			enrichmentConfig.ExecutableHash.Enabled = true
		case executableHashModeFlag:
			enrichmentConfig.ExecutableHash.Mode = parts[1]
			enrichmentConfig.ExecutableHash.Enabled = true // Setting executable-hash.mode enables executable-hash
		case userStackFlag:
			enrichmentConfig.UserStack = true
		case decodedDataFlag:
			enrichmentConfig.DecodedData = true
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
		flag == fdPathsFlag ||
		flag == environmentFlag ||
		flag == executableHashFlag ||
		flag == userStackFlag ||
		flag == decodedDataFlag
}

// invalidEnrichmentFlagError formats the error message for an invalid enrichment flag.
func invalidEnrichmentFlagError(flag string) string {
	return fmt.Sprintf(enrichInvalidFlagFormat, flag)
}
