package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{
	containers: make(map[string]*containerProcessTree),
	tree:       map[int]*types.ProcessInfo{},
}

func GetProcessInfo(threadID int) (*types.ProcessInfo, error) {
	return globalTree.GetProcessInfo(threadID)
}

func GetContainerRoot(containerID string) (*types.ProcessInfo, error) {
	return globalTree.GetContainerRoot(containerID)
}

func GetProcessLineage(threadID int) (types.ProcessLineage, error) {
	return globalTree.GetProcessLineage(threadID)
}

func ProcessEvent(event types.Event) error {
	return globalTree.ProcessEvent(event)
}

func PrintTree() {
	for cid, c := range globalTree.containers {
		fmt.Printf("%s:\n", cid)
		printNodeRec(c.Root, "")
	}
}

func printNodeRec(p *types.ProcessInfo, s string) {
	fmt.Println(s, " ", *p)
	for _, c := range p.ChildProcesses {
		printNodeRec(c, s+"-")
	}
}
