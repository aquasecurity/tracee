package probes

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// EnvironmentProvider defines the interface for OS and other environment information needed by probe compatibility checks.
// It is used to mock the environment in tests.
type EnvironmentProvider interface {
	GetOSReleaseID() environment.OSReleaseID
	CompareOSBaseKernelRelease(version string) (environment.KernelVersionComparison, error)
	GetKernelSymbol(symbol string) ([]*environment.KernelSymbol, error)
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

// In the Linux kernel, each BPF map type is associated with a corresponding map_ops structure that implements its operations.
// These map_ops structures must be exported and present in the kernel symbol table, allowing the BPF_MAP_TYPE macro to link them to their respective map types.
// The following map associates each BPF map type with the name of its map_ops structure.
// By checking for the presence of a map_ops symbol in the kernel symbol table, we can determine if a given map type is supported by the kernel.
var mapTypeToMapOperations = map[MapType]string{
	HashMapType:                "htab_map_ops",
	ArrayMapType:               "array_map_ops",
	ProgArrayMapType:           "prog_array_map_ops",
	PerfEventArrayMapType:      "perf_event_array_map_ops",
	PercpuHashMapType:          "htab_percpu_map_ops",
	PercpuArrayMapType:         "percpu_array_map_ops",
	StackTraceMapType:          "stack_trace_map_ops",
	CgroupArrayMapType:         "cgroup_array_map_ops",
	LruHashMapType:             "htab_lru_map_ops",
	LruPercpuHashMapType:       "htab_lru_percpu_map_ops",
	LpmTrieMapType:             "trie_map_ops",
	ArrayOfMapsMapType:         "array_of_maps_map_ops",
	HashOfMapsMapType:          "htab_of_maps_map_ops",
	DevmapMapType:              "dev_map_ops",
	SockmapMapType:             "sock_map_ops",
	CpumapMapType:              "cpu_map_ops",
	XskmapMapType:              "xsk_map_ops",
	SockhashMapType:            "sock_hash_ops",
	CgroupStorageMapType:       "cgroup_storage_map_ops",
	ReuseportSockarrayMapType:  "reuseport_array_ops",
	PercpuCgroupStorageMapType: "cgroup_storage_map_ops",
	QueueMapType:               "queue_map_ops",
	StackMapType:               "stack_map_ops",
	SkStorageMapType:           "sk_storage_map_ops",
	DevmapHashMapType:          "dev_map_hash_ops",
	StructOpsMapType:           "bpf_struct_ops_map_ops",
	RingbufMapType:             "ringbuf_map_ops",
	InodeStorageMapType:        "inode_storage_map_ops",
	TaskStorageMapType:         "task_storage_map_ops",
	BloomFilterMapType:         "bloom_filter_map_ops",
	UserRingbufMapType:         "user_ringbuf_map_ops",
	CgrpStorageMapType:         "cgrp_storage_map_ops",
	ArenaMapType:               "arena_map_ops",
}

// GetAllMapOperationSymbols returns all BPF map operation symbols that should be loaded into kallsyms
func GetAllMapOperationSymbols() []string {
	return slices.Collect(maps.Values(mapTypeToMapOperations))
}

// BPFMapTypeRequirement is a requirement that checks if the BPF map type is supported by the kernel.
type BPFMapTypeRequirement struct {
	mapType MapType
}

func NewBPFMapTypeRequirement(mapType MapType) *BPFMapTypeRequirement {
	return &BPFMapTypeRequirement{
		mapType: mapType,
	}
}

func (m *BPFMapTypeRequirement) IsCompatible(envProvider EnvironmentProvider) (bool, error) {
	mapOperationSymbol, ok := mapTypeToMapOperations[m.mapType]
	if !ok {
		return false, fmt.Errorf("map type %s not found", m.mapType.String())
	}

	// Get kernel symbols from the environment provider
	mapOperationSymbols, err := envProvider.GetKernelSymbol(mapOperationSymbol)
	if err != nil {
		if errors.Is(err, utils.ErrSymbolNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("error getting kernel symbol %s: %w", mapOperationSymbol, err)
	}

	if len(mapOperationSymbols) == 0 {
		return false, nil
	}

	return true, nil
}
