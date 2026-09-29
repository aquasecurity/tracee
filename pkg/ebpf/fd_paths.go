package ebpf

import "github.com/aquasecurity/tracee/pkg/config"

// defaultFDPathEntries matches the capacity of the map this one replaces.
const defaultFDPathEntries = 1024

// fdPathMapEntries returns the size of fd_arg_path_map for this configuration.
// The map is preallocated, so its memory is paid when the object is loaded:
// a disabled enrichment keeps the single entry a BPF map must have.
func fdPathMapEntries(output *config.OutputConfig) uint32 {
	if output == nil || !output.FdPaths {
		return 1
	}
	if output.FdPathsMaxEntries == 0 {
		return defaultFDPathEntries
	}
	return output.FdPathsMaxEntries
}
