package types

type ProcessInformationStatus uint

const (
	Forked ProcessInformationStatus = iota
	Executed
	GeneralCreated
	HollowParent
	Completed
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
	ThreadsCount    int
	IsAlive         bool
	Status          ProcessInformationStatus
}

type ProcessLineage []ProcessInfo
