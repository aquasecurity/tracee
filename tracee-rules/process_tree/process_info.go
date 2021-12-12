package process_tree

type ProcessIDs struct {
	Pid  int
	Ppid int
	Tid  int
}

type BinaryInfo struct {
	Path  string
	Hash  string
	Ctime int
}

type ProcessInfo struct {
	InContainerIDs  ProcessIDs
	InHostIDs       ProcessIDs
	ProcessName     string
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       int
	ParentProcess   *ProcessInfo
	ChildProcesses  []*ProcessInfo
	IsAlive         bool
}

func (p *ProcessInfo) GetAncestors() []*ProcessInfo {
	var ancestors []*ProcessInfo
	anc := p.ParentProcess
	for anc != nil {
		ancestors = append(ancestors, anc)
		anc = anc.ParentProcess
	}
	return ancestors
}
