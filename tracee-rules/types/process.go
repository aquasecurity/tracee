package types

type ProcessIDs struct {
	Pid  int
	Ppid int
	Tid  int
}

type BinaryInfo struct {
	Path  string
	Hash  string
	Ctime uint
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

type ProcessLineage []ProcessInfo
