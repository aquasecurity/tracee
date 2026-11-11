package events

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

func TestFileOpenMountWriteDeniedDependenciesCoverMountWriteSymbolAlternatives(t *testing.T) {
	strategy := CoreEvents[FileOpenMountWriteDenied].GetDependencies()
	alternatives := append(
		[]Dependencies{strategy.GetPrimaryDependencies()},
		strategy.GetFallbackDependencies()...,
	)

	// Each open helper must work with each mount-write helper generation.
	require.Len(t, alternatives, 6)

	openPairs := map[string][2]probes.Handle{
		"do_file_open": {probes.DoFileOpen, probes.DoFileOpenRet},
		"do_filp_open": {probes.DoFilpOpen, probes.DoFilpOpenRet},
	}
	openHandles := map[probes.Handle]struct{}{}
	for _, pair := range openPairs {
		openHandles[pair[0]] = struct{}{}
		openHandles[pair[1]] = struct{}{}
	}

	type combination struct {
		open      string
		mountPair [2]probes.Handle
	}
	mountPairs := map[[2]probes.Handle]struct{}{}
	combinations := map[combination]int{}
	localMountHandles := make([]map[probes.Handle]struct{}, 0, len(alternatives))
	allMountHandles := map[probes.Handle]struct{}{}

	for _, dependencies := range alternatives {
		required := map[probes.Handle]struct{}{}
		localMount := map[probes.Handle]struct{}{}
		for _, probe := range dependencies.GetProbes() {
			handle := probe.GetHandle()
			if probe.IsRequired() {
				required[handle] = struct{}{}
			}
			if _, isOpenProbe := openHandles[handle]; isOpenProbe || handle == probes.InodePermissionRet {
				continue
			}
			localMount[handle] = struct{}{}
			allMountHandles[handle] = struct{}{}
		}
		require.Contains(t, required, probes.InodePermissionRet)

		openName := ""
		for name, pair := range openPairs {
			_, hasEntry := required[pair[0]]
			_, hasReturn := required[pair[1]]
			if hasEntry && hasReturn {
				require.Empty(t, openName, "multiple open helper pairs are required")
				openName = name
			}
		}
		require.NotEmpty(t, openName, "no complete open helper pair is required")

		requiredMount := make([]probes.Handle, 0, 2)
		for handle := range required {
			if _, isOpenProbe := openHandles[handle]; isOpenProbe || handle == probes.InodePermissionRet {
				continue
			}
			requiredMount = append(requiredMount, handle)
		}
		require.Len(t, requiredMount, 2)
		if requiredMount[0] > requiredMount[1] {
			requiredMount[0], requiredMount[1] = requiredMount[1], requiredMount[0]
		}
		mountPair := [2]probes.Handle{requiredMount[0], requiredMount[1]}
		mountPairs[mountPair] = struct{}{}
		combinations[combination{open: openName, mountPair: mountPair}]++
		localMountHandles = append(localMountHandles, localMount)
	}

	require.Len(t, mountPairs, 3)
	require.Len(t, allMountHandles, 6)
	for _, localMount := range localMountHandles {
		require.Equal(t, allMountHandles, localMount, "each alternative must attach the other mount-write probes optionally")
	}
	for openName := range openPairs {
		for mountPair := range mountPairs {
			require.Equal(t, 1, combinations[combination{open: openName, mountPair: mountPair}])
		}
	}
}
