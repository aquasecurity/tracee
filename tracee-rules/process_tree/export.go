package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{
	containers: make(map[string]*containerProcessTree),
	tree:       map[int]*ProcessInfo{},
}

func GetProcessInfo(threadID int) (*ProcessInfo, error) {
	return globalTree.GetProcessInfo(threadID)
}

func GetContainerRoot(containerID string) (*ProcessInfo, error) {
	return globalTree.GetContainerRoot(containerID)
}

func GetProcessLineage(threadID int) (ProcessLineage, error) {
	return globalTree.GetProcessLineage(threadID)
}

func ProcessEvent(event types.Event) error {
	tevent := event.(external.Event)
	return globalTree.ProcessEvent(tevent)
}

func PrintTree() {
	for cid, c := range globalTree.containers {
		fmt.Printf("%s:\n", cid)
		printNodeRec(c.Root, "")
	}
}

func printNodeRec(p *ProcessInfo, s string) {
	fmt.Println(s, " ", *p)
	for _, c := range p.ChildProcesses {
		printNodeRec(c, s+"-")
	}
}
