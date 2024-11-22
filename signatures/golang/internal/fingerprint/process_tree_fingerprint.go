package fingerprint

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru/v2"
)

type ProcessTreeFingerprint struct {
	processKeyToFingerprintCache *lru.Cache[uint32, *ProcessFingerprint]
	rootProcessFingerprint       *ProcessFingerprint
}

func NewProcessTreeFingerprint(rootProcessFingerprint *ProcessFingerprint) (*ProcessTreeFingerprint, error) {
	processKeyToFingerprintCache, err := lru.New[uint32, *ProcessFingerprint](1024)
	if err != nil {
		return nil, err
	}

	return &ProcessTreeFingerprint{
		processKeyToFingerprintCache: processKeyToFingerprintCache,
		rootProcessFingerprint:       rootProcessFingerprint,
	}, nil
}

// Given access to the process tree of the system, and the current event with metadata regarding the process in which it occured, the process in which the event occurred can
// be mapped to a fingerprint in the parallel process fingerprint tree. This method take in `processTreeDataSource`, which provides an API to tracee's internal process tree,
// and `event`, the event with the process metadata, and finds of creates the relevant node in the parallel fingerprint process tree.
func (processTreeFingeprint *ProcessTreeFingerprint) GetOrCreateNodeForEvent(processTreeDataSource detect.DataSource, event *trace.Event) (*ProcessFingerprint, error) {
	// processTreeQueryAnswer, err := processTreeDataSource.Get(
	// 	datasource.ProcKey{
	// 		EntityId: event.ProcessEntityId,
	// 		Time:     time.Unix(0, int64(event.Timestamp)),
	// 	})
	// if err != nil {
	// 	return fmt.Errorf(debug("Could not find process in data source tracee/process_tree"))
	// }

	// processInfo, ok := procQueryAnswer["process_info"].(datasource.ProcessInfo)
	// if !ok {
	// 	return fmt.Errorf(debug("Could not extract process info"))
	// }

	fingerprint, ok := processTreeFingeprint.processKeyToFingerprintCache.Get(event.ProcessEntityId)
	if ok {
		return fingerprint, nil
	}

	var eventProcessLineage *datasource.ProcessLineage

	// TODO (draft code below high-level algorithm):
	//  * Fetch _full_ process lineage (should be infrequent due to the cache)
	//  * Check if process has an ancestory with the relevant command for the fingerprint
	//    * If not, scrap it
	//    * If so, traverse the process fingerprint tree with knowledge of the common ancestory process / fingerprint

	// TODO: Rollup `Cmd []string` to `Cmd string` for compatibility

	eventProcessLineageLength := len(*eventProcessLineage)
	if (*eventProcessLineage)[eventProcessLineageLength-1].Info.Cmd != processTreeFingeprint.rootProcessFingerprint.Cmd {
		return nil, fmt.Errorf(
			"Root of process lineage did not align with root of process fingerprint tree: %v - %v",
			(*eventProcessLineage)[eventProcessLineageLength-1].Info,
			*processTreeFingeprint.rootProcessFingerprint,
		)
	}

	parentFingerprint := processTreeFingeprint.rootProcessFingerprint
	for i := range eventProcessLineageLength - 2 {
		childProcess := (*eventProcessLineage)[i]
		childFingerprint, ok := fingerprint.Children[childProcess.Info.Cmd]
		if !ok {
			childFingerprint := NewProcessFingerprint(childProcess.Info.Cmd)
			parentFingerprint.AddChild(childFingerprint)
			processTreeFingeprint.processKeyToFingerprintCache.Add(childProcess.EntityId, childFingerprint) // TODO: Should the process fingerprint be added to the cache if it's not the process in which the event occured?
		}
		parentFingerprint = childFingerprint
	}

	return parentFingerprint, nil
}
