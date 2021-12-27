package types

import "github.com/RoaringBitmap/roaring"

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
	InContainerIDs  ProcessIDs
	InHostIDs       ProcessIDs
	ContainerID     string
	ProcessName     string
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       int
	ExecTime        int
	ParentProcess   *ProcessInfo
	ChildProcesses  []*ProcessInfo
	ThreadsCount    int
	IsAlive         bool
	Status          roaring.Bitmap // Values type are ProcessInformationStatus
}

type ProcessLineage []ProcessInfo
