package process_tree

import "github.com/aquasecurity/tracee/tracee-ebpf/external"

// The process tree instance to be used by the engine and the signatures
var globalTree = ProcessTree{tree: make(map[string]*containerProcessTree)}

func GetProcessInfo(containerID string, threadID int) (*ProcessInfo, error) {
	return globalTree.GetProcessInfo(containerID, threadID)
}

func GetContainerRoot(containerID string) (*ProcessInfo, error) {
	return globalTree.GetContainerRoot(containerID)
}

func ProcessEvent(event external.Event) error {
	return globalTree.ProcessEvent(event)
}
