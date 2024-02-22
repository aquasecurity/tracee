package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

//
// Probe
//

type Probe interface {
	// attach attaches the probe's program to its hook.
	attach(module *bpf.Module, args ...interface{}) error
	// detach detaches the probe's program from its hook.
	detach(...interface{}) error
	// autoload sets the probe's ebpf program automatic attaching to its hook.
	autoload(module *bpf.Module, autoload bool) error
}

//
// Event Probe Handles
//

type Handle int32

const (
	SysEnter Handle = iota
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
	KernelWrite
	KernelWriteRet
	VfsWriteMagic
	VfsWriteMagicRet
	VfsWriteVMagic
	VfsWriteVMagicRet
	KernelWriteMagic
	KernelWriteMagicRet
	SecurityMmapAddr
	SecurityMmapFile
	SecurityFileMProtect
	CommitCreds
	SwitchTaskNS
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
	SignalCgroupMkdir
	SignalCgroupRmdir
	SignalSchedProcessFork
	SignalSchedProcessExec
	SignalSchedProcessExit
)
