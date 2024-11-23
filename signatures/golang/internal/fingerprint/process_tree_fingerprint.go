package fingerprint

import (
	"log"
	"time"

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
func (processTreeFingeprint *ProcessTreeFingerprint) GetOrCreateNodeForEvent(processTreeDataSource detect.DataSource, event *trace.Event) (*ProcessFingerprint, bool) {
	// Try to retrieve fingerprint cached as relevant to the process
	fingerprint, ok := processTreeFingeprint.processKeyToFingerprintCache.Get(event.ProcessEntityId)
	if ok {
		return fingerprint, true
	}

	// TODO (draft code below high-level algorithm):
	//  * Fetch _full_ process lineage (should be infrequent due to the cache)
	//  * Check if process has an ancestory with the relevant command for the fingerprint
	//    * If not, scrap it
	//    * If so, traverse the process fingerprint tree with knowledge of the common ancestory process / fingerprint

	// Fetch the full process lineage of the event's process
	maxDepth := 25 // up to 5 ancestors + process itself
	lineageQueryAnswer, err := processTreeDataSource.Get(
		datasource.LineageKey{
			EntityId: event.ProcessEntityId,
			Time:     time.Unix(0, int64(event.Timestamp)),
			MaxDepth: maxDepth,
		},
	)
	if err != nil {
		log.Printf("Could not find process lineage for event ProcessEntityId: %v", event.ProcessEntityId)
		return nil, false
	}
	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
	if !ok {
		log.Printf("Could not extract process lineage from retrieved process lineage information: %v", lineageQueryAnswer)
		return nil, false
	}

	// Search for the process in the process lineage that corresponds to the root of the process fingerprint tree.
	// If it can't be found, it means that this event is not a descendant of the process being fingerprinted, and
	// no process fingerprint should be created nor returned.
	var eventProcessLineage datasource.ProcessLineage
	isDescendantOfRootProcess := false
	for i, ancestor := range lineageInfo {
		if ancestor.Info.Cmd == processTreeFingeprint.rootProcessFingerprint.Cmd {
			eventProcessLineage = lineageInfo[0 : i+1]
			isDescendantOfRootProcess = true
			break
		}
	}
	if !isDescendantOfRootProcess {
		return nil, false // TODO: Flag when fingerprint isn't retrieved or created
	}

	// Traverse the tree from the root process fingerprint, adding child process fingerprints if necessary along the way,
	// until the event process fingerprint has been created.
	eventProcessLineageLength := len(eventProcessLineage)
	parentFingerprint := processTreeFingeprint.rootProcessFingerprint
	for i := eventProcessLineageLength - 2; i >= 0; i-- {
		childProcess := eventProcessLineage[i]
		childFingerprint, ok := fingerprint.Children[childProcess.Info.Cmd]
		if !ok {
			childFingerprint := NewProcessFingerprint(childProcess.Info.Cmd)
			parentFingerprint.AddChild(childFingerprint)
			processTreeFingeprint.processKeyToFingerprintCache.Add(childProcess.Info.EntityId, childFingerprint) // TODO: Should the process fingerprint be added to the cache if it's not the process in which the event occured?
		}
		parentFingerprint = childFingerprint
	}

	return parentFingerprint, true
}
