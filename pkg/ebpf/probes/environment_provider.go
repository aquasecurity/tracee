package probes

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/aquasecurity/tracee/common/environment"
)

// EnvironmentProviderAdapter adapts OSInfo and KernelConfig to implement the EnvironmentProvider interface.
// It combines OS information and kernel configuration for probe compatibility checks.
type EnvironmentProviderAdapter struct {
	osInfo       *environment.OSInfo
	kernelConfig *environment.KernelConfig
	filesystem   fs.FS
}

// NewEnvironmentProviderAdapter creates a new adapter with OSInfo and KernelConfig.
// Uses the OS filesystem by default.
func NewEnvironmentProviderAdapter(osInfo *environment.OSInfo, kernelConfig *environment.KernelConfig) *EnvironmentProviderAdapter {
	return &EnvironmentProviderAdapter{
		osInfo:       osInfo,
		kernelConfig: kernelConfig,
		filesystem:   os.DirFS("/"),
	}
}

// NewEnvironmentProviderAdapterWithFS creates a new adapter with a custom filesystem.
// This is useful for testing with mock filesystems.
func NewEnvironmentProviderAdapterWithFS(osInfo *environment.OSInfo, kernelConfig *environment.KernelConfig, filesystem fs.FS) *EnvironmentProviderAdapter {
	return &EnvironmentProviderAdapter{
		osInfo:       osInfo,
		kernelConfig: kernelConfig,
		filesystem:   filesystem,
	}
}

// GetOSReleaseID returns the OS release ID, delegating to OSInfo
func (e *EnvironmentProviderAdapter) GetOSReleaseID() environment.OSReleaseID {
	return e.osInfo.GetOSReleaseID()
}

// CompareOSBaseKernelRelease compares kernel versions, delegating to OSInfo
func (e *EnvironmentProviderAdapter) CompareOSBaseKernelRelease(version string) (environment.KernelVersionComparison, error) {
	return e.osInfo.CompareOSBaseKernelRelease(version)
}

// GetKernelConfigValue returns the type and string value of a kernel config option, or UNDEFINED and an error if not found.
// For STRING options, the string is the actual config value; for others, it's their label.
func (e *EnvironmentProviderAdapter) GetKernelConfigValue(option environment.KernelConfigOption) (environment.KernelConfigOptionValue, string, error) {
	value := e.kernelConfig.GetValue(option)
	if value == environment.UNDEFINED {
		return environment.UNDEFINED, "", fmt.Errorf("kernel config option %s not found", option.String())
	}

	if value == environment.STRING {
		strValue, err := e.kernelConfig.GetValueString(option)
		return environment.STRING, strValue, err
	}

	return value, value.String(), nil
}

// GetFilesystem returns the filesystem instance used by this provider.
func (e *EnvironmentProviderAdapter) GetFilesystem() fs.FS {
	return e.filesystem
}
