package probes

import (
	"strings"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// ProbeCompatibility stores the requirements for a probe to be used.
// It is used to check if a probe is compatible with the current OS.
type ProbeCompatibility struct {
	probe        Handle
	requirements []ProbeRequirement
}

func NewProbeCompatibility(probe Handle, requirements []ProbeRequirement) *ProbeCompatibility {
	return &ProbeCompatibility{
		probe:        probe,
		requirements: requirements,
	}
}

// IsCompatible checks if the probe is compatible with the current OS.
func (p *ProbeCompatibility) IsCompatible(osInfo OSInfoProvider) (bool, error) {
	isAllCompatible := true
	for _, requirement := range p.requirements {
		isCompatible, err := requirement.IsCompatible(osInfo)
		if err != nil {
			return false, err
		}
		isAllCompatible = isAllCompatible && isCompatible
	}
	return isAllCompatible, nil
}

// ProbeRequirement is an interface that defines the requirements for a probe to be used.
type ProbeRequirement interface {
	IsCompatible(osInfo OSInfoProvider) (bool, error)
}

// KernelVersionRequirement is a requirement that checks if the kernel version and distro are compatibles.
type KernelVersionRequirement struct {
	distro           string
	minKernelVersion string
	maxKernelVersion string
}

// NewKernelVersionRequirement creates a new KernelVersionRequirement.
func NewKernelVersionRequirement(distro, minKernelVersion, maxKernelVersion string) *KernelVersionRequirement {
	return &KernelVersionRequirement{
		distro:           distro,
		minKernelVersion: minKernelVersion,
		maxKernelVersion: maxKernelVersion,
	}
}

// IsCompatible checks if the kernel version and distro are compatibles.
func (k *KernelVersionRequirement) IsCompatible(osInfo OSInfoProvider) (bool, error) {
	// If distro is specified, check if it matches
	// Only if the distro is matching then the kernel version is relevant.
	// Empty distro means that the kernel version is relevant for all distros.
	if k.distro != "" && osInfo.GetOSReleaseID().String() != strings.ToLower(k.distro) {
		return true, nil
	}

	// If minKernelVersion is specified, check if osInfo.KernelVersion >= minKernelVersion
	if k.minKernelVersion != "" {
		comparison, err := osInfo.CompareOSBaseKernelRelease(k.minKernelVersion)
		if err != nil {
			return false, err
		}
		if comparison == environment.KernelVersionNewer {
			return false, nil
		}
	}

	// If maxKernelVersion is specified, check if osInfo.KernelVersion <= maxKernelVersion
	if k.maxKernelVersion != "" {
		comparison, err := osInfo.CompareOSBaseKernelRelease(k.maxKernelVersion)
		if err != nil {
			return false, err
		}
		if comparison == environment.KernelVersionOlder {
			return false, nil
		}
	}

	return true, nil
}
