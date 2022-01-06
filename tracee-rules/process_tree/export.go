package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"log"
)

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{
	processes: map[int]*processNode{},
}

func GetProcessInfo(hostProcessID int) (types.ProcessInfo, error) {
	pn, err := globalTree.GetProcessInfo(hostProcessID)
	if err != nil {
		return types.ProcessInfo{}, err
	}
	return pn.Export(), nil
}

func GetProcessLineage(hostProcessID int) (types.ProcessLineage, error) {
	pList, err := globalTree.GetProcessLineage(hostProcessID)
	if err != nil {
		return nil, err
	}
	lineage := make(types.ProcessLineage, len(pList))
	for i, p := range pList {
		lineage[i] = p.Export()
	}
	return lineage, nil
}

func ProcessEvent(event types.Event) error {
	return globalTree.ProcessEvent(event)
}

func CreateProcessTreeInputPipeline(in chan types.Event) chan types.Event {
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
	close(out)
}

func CreateProcessTreeOutputEnrichmentPipeline(out chan types.Finding) chan types.Finding {
	in := make(chan types.Finding)
	go func() {
		for f := range in {
			if f.ExtendedContext == nil {
				f.ExtendedContext = make(map[string]interface{})
			}
			e, ok := f.Context.(external.Event)
			if ok {
				pLineage, err := GetProcessLineage(e.HostProcessID)
				if err == nil {
					f.ExtendedContext["process-lineage"] = pLineage
				}
			}
			out <- f
		}
	}()
	return in
}

func (p *processNode) Export() types.ProcessInfo {
	return types.ProcessInfo{
		InContainerIDs:  p.InContainerIDs,
		InHostIDs:       p.InHostIDs,
		ContainerID:     p.ContainerID,
		ProcessName:     p.ProcessName,
		Cmd:             p.Cmd,
		ExecutionBinary: p.ExecutionBinary,
		StartTime:       p.StartTime,
		ExecTime:        p.ExecTime,
		ExistingThreads: p.ExistingThreads,
		IsAlive:         p.IsAlive,
	}
}
