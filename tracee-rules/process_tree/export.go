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

func GetProcessInfo(hostProcessID int, time int) (types.ProcessInfo, error) {
	pn, err := globalTree.GetProcessInfo(hostProcessID)
	if err != nil {
		return types.ProcessInfo{}, err
	}
	return pn.export(time), nil
}

func GetProcessLineage(hostProcessID int, time int) (types.ProcessLineage, error) {
	pList, err := globalTree.GetProcessLineage(hostProcessID)
	if err != nil {
		return nil, err
	}
	lineage := make(types.ProcessLineage, len(pList))
	for i, p := range pList {
		lineage[i] = p.export(time)
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
				pLineage, err := GetProcessLineage(e.HostProcessID, e.Timestamp)
				if err == nil {
					f.ExtendedContext["process-lineage"] = pLineage
				}
			}
			out <- f
		}
	}()
	return in
}

func (p *processNode) export(time int) types.ProcessInfo {
	var childrenIDs []int
	var threadIDs []int
	for _, child := range p.ChildProcesses {
		childrenIDs = append(childrenIDs, child.InHostIDs.Pid)
	}
	for tid, threadExitTime := range p.ThreadsExits {
		if threadExitTime != 0 &&
			time > int(threadExitTime) {
			threadIDs = append(threadIDs, tid)
		}
	}
	isAlive := (p.IsAlive == true) || (time < int(p.ExitTime))
	return types.ProcessInfo{
		InContainerIDs:       p.InContainerIDs,
		InHostIDs:            p.InHostIDs,
		ContainerID:          p.ContainerID,
		ProcessName:          p.ProcessName,
		Cmd:                  p.Cmd,
		ExecutionBinary:      p.ExecutionBinary,
		StartTime:            int(p.StartTime),
		ExecTime:             int(p.ExecTime),
		ExistingThreads:      threadIDs,
		IsAlive:              isAlive,
		ChildrenProcessesIDs: childrenIDs,
	}
}
