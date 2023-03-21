// Package bufferdecoder implements the structs (protocol indeed) used in the communication
// between code eBPF running in the Kernel and the Tracee-eBPF user-space application.
package bufferdecoder

import "github.com/aquasecurity/tracee/pkg/events"

// BinType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type BinType uint8

const (
	SendVfsWrite BinType = iota + 1
	SendMprotect
	SendKernelModule
	SendBpfObject
)

// PLEASE NOTE, YOU MUST UPDATE THE DECODER IF ANY CHANGE TO THIS STRUCT IS DONE.

// Context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
// NOTE: Integers want to be aligned in memory, so if changing the format of this struct
// keep the 1-byte 'Argnum' as the final parameter before the padding (if padding is needed).
type Context struct {
	Ts              uint64
	StartTime       uint64
	CgroupID        uint64
	Pid             uint32
	Tid             uint32
	Ppid            uint32
	HostPid         uint32
	HostTid         uint32
	HostPpid        uint32
	Uid             uint32
	MntID           uint32
	PidID           uint32
	Comm            [16]byte
	UtsName         [16]byte
	Flags           uint32
	EventID         events.ID //int32
	Syscall         int32
	MatchedPolicies uint64
	Retval          int64
	StackID         uint32
	ProcessorId     uint16
	Argnum          uint8
	_               [1]byte //padding
}

func (Context) GetSizeBytes() uint32 {
	return 128
}

type ChunkMeta struct {
	BinType  BinType
	CgroupID uint64
	Metadata [28]byte
	Size     int32
	Off      uint64
}

func (ChunkMeta) GetSizeBytes() uint32 {
	return 49
}

type VfsWriteMeta struct {
	DevID uint32
	Inode uint64
	Mode  uint32
	Pid   uint32
}

func (VfsWriteMeta) GetSizeBytes() uint32 {
	return 20
}

type KernelModuleMeta struct {
	DevID uint32
	Inode uint64
	Pid   uint32
	Size  uint32
}

func (KernelModuleMeta) GetSizeBytes() uint32 {
	return 20
}

type BpfObjectMeta struct {
	Name [16]byte
	Rand uint32
	Pid  uint32
	Size uint32
}

func (BpfObjectMeta) GetSizeBytes() uint32 {
	return 28
}

type MprotectWriteMeta struct {
	Ts uint64
}

func (MprotectWriteMeta) GetSizeBytes() uint32 {
	return 8
}

// SlimCred struct is a slim version of the kernel's cred struct
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `slim_cred_t` struct in the ebpf code.
// ANY CHANGE TO THIS STRUCT WILL BE REQUIRED ALSO TO detect.SlimCred and bufferdecoder.SlimCred
type SlimCred struct {
	Uid            uint32 /* real UID of the task */
	Gid            uint32 /* real GID of the task */
	Suid           uint32 /* saved UID of the task */
	Sgid           uint32 /* saved GID of the task */
	Euid           uint32 /* effective UID of the task */
	Egid           uint32 /* effective GID of the task */
	Fsuid          uint32 /* UID for VFS ops */
	Fsgid          uint32 /* GID for VFS ops */
	UserNamespace  uint32 /* User Namespace of the of the event */
	SecureBits     uint32 /* SUID-less security management */
	CapInheritable uint64 /* caps our children can inherit */
	CapPermitted   uint64 /* caps we're permitted */
	CapEffective   uint64 /* caps we can actually use */
	CapBounding    uint64 /* capability bounding set */
	CapAmbient     uint64 /* Ambient capability set */
}

func (s SlimCred) GetSizeBytes() uint32 {
	return 80
}
