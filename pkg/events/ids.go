package events

type ID int32

// Common events (used by all architectures).
// Events should match defined values in ebpf code.
const (
	NetPacketBase ID = iota + 700
	NetPacketIPBase
	NetPacketTCPBase
	NetPacketUDPBase
	NetPacketICMPBase
	NetPacketICMPv6Base
	NetPacketDNSBase
	NetPacketHTTPBase
	NetPacketCapture
	MaxNetID // network base events go ABOVE this item
	SysEnter
	SysExit
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWritev
	VfsRead
	VfsReadv
	MemProtAlert
	CommitCreds
	SwitchTaskNS
	MagicWrite
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	SecurityBprmCheck
	SecurityFileOpen
	SecurityInodeUnlink
	SecuritySocketCreate
	SecuritySocketListen
	SecuritySocketConnect
	SecuritySocketAccept
	SecuritySocketBind
	SecuritySocketSetsockopt
	SecuritySbMount
	SecurityBPF
	SecurityBPFMap
	SecurityKernelReadFile
	SecurityInodeMknod
	SecurityPostReadFile
	SecurityInodeSymlinkEventId
	SecurityMmapFile
	SecurityFileMprotect
	SocketDup
	HiddenInodes
	KernelWrite
	ProcCreate
	KprobeAttach
	CallUsermodeHelper
	DirtyPipeSplice
	DebugfsCreateFile
	PrintSyscallTable
	DebugfsCreateDir
	DeviceAdd
	RegisterChrdev
	SharedObjectLoaded
	DoInitModule
	SocketAccept
	LoadElfPhdrs
	HookedProcFops
	PrintNetSeqOps
	TaskRename
	SecurityInodeRename
	DoSigaction
	BpfAttach
	KallsymsLookupName
	DoMmap
	PrintMemDump
	VfsUtimes
	DoTruncate
	FileModification
	InotifyWatch
	SecurityBpfProg
	ProcessExecuteFailed
	HiddenKernelModuleSeeker
	ModuleLoad
	ModuleFree
	MaxCommonID
)

// Events originated from user-space
const (
	NetPacketIPv4 ID = iota + 2000
	NetPacketIPv6
	NetPacketTCP
	NetPacketUDP
	NetPacketICMP
	NetPacketICMPv6
	NetPacketDNS
	NetPacketDNSRequest
	NetPacketDNSResponse
	NetPacketHTTP
	NetPacketHTTPRequest
	NetPacketHTTPResponse
	MaxUserNetID
	InitNamespaces
	ContainerCreate
	ContainerRemove
	ExistingContainer
	HookedSyscalls
	HookedSeqOps
	SymbolsLoaded
	SymbolsCollision
	HiddenKernelModule
	MaxUserSpace
)

// Capture meta-events
const (
	CaptureFileWrite ID = iota + 4000
	CaptureExec
	CaptureModule
	CaptureMem
	CapturePcap
	CaptureNetPacket
	CaptureBpf
	CaptureFileRead
)

// Signature events
const (
	StartSignatureID ID = 6000
	MaxSignatureID   ID = 6999
)
