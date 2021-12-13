package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{tree: make(map[string]*containerProcessTree)}

func GetProcessInfo(containerID string, threadID int) (*ProcessInfo, error) {
	return globalTree.GetProcessInfo(containerID, threadID)
}

func GetContainerRoot(containerID string) (*ProcessInfo, error) {
	return globalTree.GetContainerRoot(containerID)
}

func ProcessEvent(event types.Event) error {
	tevent := event.(external.Event)
	return globalTree.ProcessEvent(tevent)
}

func PrintTree() {
	for cid, c := range globalTree.tree {
		fmt.Printf("%s:\n", cid)
		printNodeRec(c.root, "")
	}
}

func printNodeRec(p *ProcessInfo, s string) {
	fmt.Println(s, " ", *p)
	for _, c := range p.ChildProcesses {
		printNodeRec(c, s+"-")
	}
}
