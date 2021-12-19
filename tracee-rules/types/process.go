package types

type ProcessStatus uint

const (
	Forked ProcessStatus = iota
	Executed
	GeneralCreated
	HollowParent
	Complete
)

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
	ContainerID     string
	ProcessName     string
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       int
	ParentProcess   *ProcessInfo
	ChildProcesses  []*ProcessInfo
	IsAlive         bool
	Status          ProcessStatus
}

type ProcessLineage []ProcessInfo
