package probes

type Probe interface {
	// Attach attaches the probe's program to its hook.
	Attach(args ...interface{}) error
	// Detach detaches the probe's program from its hook.
	Detach(...interface{}) error
	// SetAutoload sets the probe's ebpf program automatic attaching to its hook.
	SetAutoload(autoload bool) error
}

// Event Probe Handles

type ProbeHandle int32

const (
	SysEnter ProbeHandle = iota
	SysExit
	SyscallEnter__Internal
	SyscallExit__Internal
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedProcessFree
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWriteRet
	VfsWriteV
	VfsWriteVRet
	SecurityMmapAddr
	SecurityMmapFile
	SecurityFileMProtect
	CommitCreds
	SwitchTaskNS
	KernelWrite
	KernelWriteRet
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	SecurityBPRMCheck
	SecurityFileOpen
	SecurityInodeUnlink
	SecurityInodeMknod
	SecurityInodeSymlink
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
	SecurityKernelPostReadFile
	DoSplice
	DoSpliceRet
	ProcCreate
	RegisterKprobe
	RegisterKprobeRet
	CallUsermodeHelper
	DebugfsCreateFile
	DebugfsCreateDir
	DeviceAdd
	RegisterChrdev
	RegisterChrdevRet
	DoInitModule
	DoInitModuleRet
	LoadElfPhdrs
	Filldir64
	SecurityFilePermission
	TaskRename
	SyscallTableCheck
	PrintNetSeqOps
	SecurityInodeRename
	DoSigaction
	SecurityBpfProg
	SecurityFileIoctl
	CheckHelperCall
	CheckMapFuncCompatibility
	KallsymsLookupName
	KallsymsLookupNameRet
	SockAllocFile
	SockAllocFileRet
	SecuritySkClone
	SecuritySocketRecvmsg
	SecuritySocketSendmsg
	CgroupBPFRunFilterSKB
	CgroupSKBIngress
	CgroupSKBEgress
	DoMmap
	DoMmapRet
	PrintMemDump
	VfsRead
	VfsReadRet
	VfsReadV
	VfsReadVRet
	VfsUtimes
	UtimesCommon
	DoTruncate
	FileUpdateTime
	FileUpdateTimeRet
	FileModified
	FileModifiedRet
	FdInstall
	FilpClose
	InotifyFindInode
	InotifyFindInodeRet
	BpfCheck
	ExecBinprm
	ExecBinprmRet
	HiddenKernelModuleSeeker
	TpProbeRegPrioMayExist
	HiddenKernelModuleVerifier
	ModuleLoad
	ModuleFree
	LayoutAndAllocate
	SignalCgroupMkdir
	SignalCgroupRmdir
	SignalSchedProcessFork
	SignalSchedProcessExec
	SignalSchedProcessExit
)
