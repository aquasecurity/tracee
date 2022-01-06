package types

type ProcessInformationStatus uint32

const (
	Forked ProcessInformationStatus = iota
	Executed
	GeneralCreated
	HollowParent
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
	InContainerIDs       ProcessIDs
	InHostIDs            ProcessIDs
	ContainerID          string
	ProcessName          string
	Cmd                  []string
	ExecutionBinary      BinaryInfo
	StartTime            int
	ExecTime             int
	ExistingThreads      []int
	IsAlive              bool
	ChildrenProcessesIDs []int
}

type ProcessLineage []ProcessInfo
