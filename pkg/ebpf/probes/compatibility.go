package probes

import (
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/environment"
)

// EnvironmentProvider defines the interface for OS and other environment information needed by probe compatibility checks
// For now, it is a wrapper around environment.OsInfo object to allow easier mocking in tests
type EnvironmentProvider interface {
	GetOSReleaseID() environment.OSReleaseID
	CompareOSBaseKernelRelease(version string) (environment.KernelVersionComparison, error)
}

// ProbeCompatibility stores the requirements for a probe to be used.
// It is used to check if a probe is compatible with the current OS.
type ProbeCompatibility struct {
	requirements []ProbeRequirement
}

func NewProbeCompatibility(requirements ...ProbeRequirement) *ProbeCompatibility {
	return &ProbeCompatibility{
		requirements: requirements,
	}
}

// IsCompatible checks if the probe is compatible with the current OS.
func (p *ProbeCompatibility) isCompatible(envProvider EnvironmentProvider) (bool, error) {
	isAllCompatible := true
	for _, requirement := range p.requirements {
		isCompatible, err := requirement.IsCompatible(envProvider)
		if err != nil {
			return false, err
		}
		isAllCompatible = isAllCompatible && isCompatible
	}
	return isAllCompatible, nil
}

// ProbeRequirement is an interface that defines the requirements for a probe to be used.
type ProbeRequirement interface {
	IsCompatible(envProvider EnvironmentProvider) (bool, error)
}

// KernelVersionRequirement is a requirement that checks if the kernel version and distro are compatible.
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

// IsCompatible checks if the kernel version and distro are compatible.
func (k *KernelVersionRequirement) IsCompatible(envProvider EnvironmentProvider) (bool, error) {
	// If distro is specified, check if it matches
	// Only if the distro is matching then the kernel version is relevant.
	// Empty distro means that the kernel version is relevant for all distros.
	if k.distro != "" && envProvider.GetOSReleaseID().String() != strings.ToLower(k.distro) {
		return true, nil
	}

	// If minKernelVersion is specified, check if envProvider.KernelVersion >= minKernelVersion
	if k.minKernelVersion != "" {
		comparison, err := envProvider.CompareOSBaseKernelRelease(k.minKernelVersion)
		if err != nil {
			return false, err
		}
		// If provided kernel version is newer, the probe is under the minimum version, so it is not compatible.
		if comparison == environment.KernelVersionNewer {
			return false, nil
		}
	}

	// If maxKernelVersion is specified, check if envProvider.KernelVersion <= maxKernelVersion
	if k.maxKernelVersion != "" {
		comparison, err := envProvider.CompareOSBaseKernelRelease(k.maxKernelVersion)
		if err != nil {
			return false, err
		}
		// If provided kernel version is older, the probe is over the maximum version, so it is not compatible.
		if comparison == environment.KernelVersionOlder {
			return false, nil
		}
	}

	return true, nil
}

// MapTypeSupportChecker is a function type used for dependency injection to check BPF map type support.
// This allows tests to inject mock implementations, making BPF compatibility logic testable and decoupled from the environment.
type MapTypeSupportChecker func(mapType bpf.MapType) (bool, error)

// BPFMapTypeRequirement specifies a requirement for kernel support of a particular BPF map type.
type BPFMapTypeRequirement struct {
	mapType bpf.MapType
	checker MapTypeSupportChecker
}

func NewBPFMapTypeRequirement(mapType bpf.MapType) *BPFMapTypeRequirement {
	return &BPFMapTypeRequirement{
		mapType: mapType,
		checker: bpf.BPFMapTypeIsSupported,
	}
}

func NewBPFMapTypeRequirementWithChecker(mapType bpf.MapType, checker MapTypeSupportChecker) *BPFMapTypeRequirement {
	return &BPFMapTypeRequirement{
		mapType: mapType,
		checker: checker,
	}
}

// IsCompatible checks if the kernel supports the BPF map type.
// This check is whether the kernel supports the BPF map type, both by implementation and configuration.
func (m *BPFMapTypeRequirement) IsCompatible(_ EnvironmentProvider) (bool, error) {
	return m.checker(m.mapType)
}

// ProgramTypeSupportChecker is a function type used for dependency injection to check BPF program type support.
// This allows tests to inject mock implementations, making BPF compatibility logic testable and decoupled from the environment.
type ProgramTypeSupportChecker func(progType bpf.BPFProgType) (bool, error)

// BpfProgramRequirement specifies a requirement for kernel support of a particular BPF program type.
type BpfProgramRequirement struct {
	bpfProgramType bpf.BPFProgType
	checker        ProgramTypeSupportChecker
}

func NewBpfProgramRequirement(progType bpf.BPFProgType) *BpfProgramRequirement {
	return &BpfProgramRequirement{
		bpfProgramType: progType,
		checker:        bpf.BPFProgramTypeIsSupported,
	}
}

func NewBpfProgramRequirementWithChecker(progType bpf.BPFProgType, checker ProgramTypeSupportChecker) *BpfProgramRequirement {
	return &BpfProgramRequirement{
		bpfProgramType: progType,
		checker:        checker,
	}
}

// IsCompatible checks if the kernel supports the BPF program type.
// This check is whether the kernel supports the BPF program type, both by implementation and configuration.
func (b *BpfProgramRequirement) IsCompatible(_ EnvironmentProvider) (bool, error) {
	return b.checker(b.bpfProgramType)
}
