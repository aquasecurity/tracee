package process_tree

import (
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"log"
)

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{
	processes: map[int]*types.ProcessInfo{},
}

func GetProcessInfo(hostProcessID int) (*types.ProcessInfo, error) {
	return globalTree.GetProcessInfo(hostProcessID)
}

func GetProcessLineage(hostProcessID int) (types.ProcessLineage, error) {
	return globalTree.GetProcessLineage(hostProcessID)
}

func ProcessEvent(event types.Event) error {
	return globalTree.ProcessEvent(event)
}

func CreateProcessTreePipeline(in chan types.Event) chan types.Event {
	out := make(chan types.Event, 100)
	go processTreeStart(in, out)
	return out
}

func processTreeStart(in chan types.Event, out chan types.Event) {
	for e := range in {
		err := ProcessEvent(e)
		if err != nil {
			log.Printf("error processing event in process tree: %v", err)
		}
		out <- e
	}
}
