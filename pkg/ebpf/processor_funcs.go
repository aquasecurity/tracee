package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/filehash"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/types/trace"
)

// processWriteEvent processes a write event by indexing the written file.
func (t *Tracee) processWriteEvent(event *trace.Event) error {
	// only capture written files
	if !t.config.Capture.FileWrite.Capture {
		return nil
	}
	filePath, err := parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		return errfmt.Errorf("error parsing vfs_write args: %v", err)
	}
	// path should be absolute, except for e.g memfd_create files
	if filePath == "" || filePath[0] != '/' {
		return nil
	}
	dev, err := parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return errfmt.Errorf("error parsing vfs_write args: %v", err)
	}
	inode, err := parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return errfmt.Errorf("error parsing vfs_write args: %v", err)
	}

	// stop processing if write was already indexed
	containerId := event.Container.ID
	if containerId == "" {
		containerId = "host"
	}
	fileName := fmt.Sprintf("%s/write.dev-%d.inode-%d", containerId, dev, inode)
	indexName, ok := t.writtenFiles[fileName]
	if ok && indexName == filePath {
		return nil
	}

	// index written file by original filepath
	t.writtenFiles[fileName] = filePath
	return nil
}

// processReadEvent processes a read event by indexing the read file.
func (t *Tracee) processReadEvent(event *trace.Event) error {
	// only capture read files
	if !t.config.Capture.FileRead.Capture {
		return nil
	}
	filePath, err := parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		return fmt.Errorf("error parsing vfs_read args: %v", err)
	}
	// path should be absolute, except for e.g memfd_create files
	if filePath == "" || filePath[0] != '/' {
		return nil
	}
	dev, err := parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return fmt.Errorf("error parsing vfs_write args: %v", err)
	}
	inode, err := parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return fmt.Errorf("error parsing vfs_write args: %v", err)
	}

	// stop processing if write was already indexed
	containerId := event.Container.ID
	if containerId == "" {
		containerId = "host"
	}
	fileName := fmt.Sprintf("%s/read.dev-%d.inode-%d", containerId, dev, inode)
	indexName, ok := t.readFiles[fileName]
	if ok && indexName == filePath {
		return nil
	}

	// index written file by original filepath
	t.readFiles[fileName] = filePath
	return nil
}

// processKernelReadFile processes a security read event and changes the read type value.
func processKernelReadFile(event *trace.Event) error {
	readTypeArg := events.GetArg(event, "type")
	readTypeInt, ok := readTypeArg.Value.(int32)
	if !ok {
		return errfmt.Errorf("missing argument %s in event %s", "type", event.EventName)
	}
	readType, idExists := kernelReadFileTypes[readTypeInt]
	if !idExists {
		return errfmt.Errorf("kernelReadFileId doesn't exist in kernelReadFileType map")
	}
	readTypeArg.Value = readType
	return nil
}

// processSchedProcessExec processes a sched_process_exec event by capturing the executed file.
func (t *Tracee) processSchedProcessExec(event *trace.Event) error {
	// cache this pid by it's mnt ns
	if event.ProcessID == 1 {
		t.pidsInMntns.ForceAddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	} else {
		t.pidsInMntns.AddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	}

	// capture executed files
	if t.config.Capture.Exec || t.config.Output.CalcHashes != config.CalcHashesNone {
		filePath, err := parse.ArgVal[string](event.Args, "pathname")
		if err != nil {
			return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
		}
		// Should be absolute path, except for e.g memfd_create files
		if filePath == "" || filePath[0] != '/' {
			return nil
		}
		// try to access the root fs via another process in the same mount namespace (as the process
		// from the current event might have already died)
		pids := t.pidsInMntns.GetBucket(uint32(event.MountNS))
		for _, pid := range pids { // will break on success
			err = nil
			sourceFilePath := fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pid)), filePath)
			sourceFileCtime, err := parse.ArgVal[uint64](event.Args, "ctime")
			if err != nil {
				return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
			}
			castedSourceFileCtime := int64(sourceFileCtime)

			containerId := event.Container.ID
			if containerId == "" {
				containerId = "host"
			}

			capturedFileID := fmt.Sprintf("%s:%s", containerId, filePath)
			// capture exec'ed files ?
			if t.config.Capture.Exec {
				destinationDirPath := containerId
				if err := utils.MkdirAtExist(t.OutDir, destinationDirPath, 0755); err != nil {
					return errfmt.WrapError(err)
				}
				destinationFilePath := filepath.Join(
					destinationDirPath,
					fmt.Sprintf(
						"exec.%d.%s",
						event.Timestamp,
						filepath.Base(filePath),
					),
				)
				// don't capture same file twice unless it was modified
				lastCtime, ok := t.capturedFiles[capturedFileID]
				if !ok || lastCtime != castedSourceFileCtime {
					// capture (SchedProcessExec sets base capabilities to have cap.SYS_PTRACE set.
					// This is needed at this point because raising and dropping capabilities too
					// frequently would have a big performance impact)
					err := utils.CopyRegularFileByRelativePath(
						sourceFilePath,
						t.OutDir,
						destinationFilePath,
					)
					if err != nil {
						logger.Debugw("capture exec: failed copying file", "error", err)
						continue
					}
					// mark this file as captured
					t.capturedFiles[capturedFileID] = castedSourceFileCtime
				}
			}
			// check exec'ed hash ?
			if t.config.Output.CalcHashes != config.CalcHashesNone {
				dev, err := parse.ArgVal[uint32](event.Args, "dev")
				if err != nil {
					return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
				}
				ino, err := parse.ArgVal[uint64](event.Args, "inode")
				if err != nil {
					return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
				}

				fileKey := filehash.NewKey(filePath, event.MountNS,
					filehash.WithDevice(dev),
					filehash.WithInode(ino, castedSourceFileCtime),
					filehash.WithDigest(event.Container.ImageDigest),
				)

				err = t.addHashArg(event, &fileKey)
				if err != nil {
					return err
				}
			}
			if true { // so loop is conditionally terminated (#SA4044)
				break
			}
		}
		return errfmt.WrapError(err)
	}
	return nil
}

// processDoFinitModule handles a do_finit_module event and triggers other hooking detection logic.
func (t *Tracee) processDoInitModule(event *trace.Event) error {
	// Check if related events are being traced.
	okSyscalls := t.policyManager.IsEventSelected(events.HookedSyscall)
	okSeqOps := t.policyManager.IsEventSelected(events.HookedSeqOps)
	okProcFops := t.policyManager.IsEventSelected(events.HookedProcFops)
	okMemDump := t.policyManager.IsEventSelected(events.PrintMemDump)
	okFtrace := t.policyManager.IsEventSelected(events.FtraceHook)

	if !okSyscalls && !okSeqOps && !okProcFops && !okMemDump && !okFtrace {
		return nil
	}

	err := capabilities.GetInstance().EBPF(
		func() error {
			newKernelSymbols, err := environment.NewKernelSymbolTable(true, true, t.requiredKsyms...)
			if err != nil {
				return errfmt.WrapError(err)
			}
			t.setKernelSymbols(newKernelSymbols)
			return t.UpdateKallsyms()
		},
	)
	if err != nil {
		return errfmt.WrapError(err)
	}
	if okSyscalls && expectedSyscallTableInit {
		// Trigger syscall table hooking detection.
		t.triggerSyscallTableIntegrityCheckCall()
	}
	if okSeqOps {
		// Trigger seq_ops hooking detection
		t.triggerSeqOpsIntegrityCheck(*event)
	}
	if okMemDump {
		errs := t.triggerMemDump(*event)
		for _, err := range errs {
			logger.Warnw("Memory dump", "error", err)
		}
	}
	if okFtrace {
		events.FtraceWakeupChan <- struct{}{}
	}

	return nil
}

const (
	IterateShared int = iota
	Iterate
)

// processHookedProcFops processes a hooked_proc_fops event.
func (t *Tracee) processHookedProcFops(event *trace.Event) error {
	const hookedFopsPointersArgName = "hooked_fops_pointers"
	fopsAddresses, err := parse.ArgVal[[]uint64](event.Args, hookedFopsPointersArgName)
	if err != nil || fopsAddresses == nil {
		return errfmt.Errorf("error parsing hooked_proc_fops args: %v", err)
	}
	hookedFops := make([]trace.HookedSymbolData, 0)
	for idx, addr := range fopsAddresses {
		if addr == 0 { // address is in text segment, marked as 0
			continue
		}
		hookingFunction := t.getKernelSymbols().GetPotentiallyHiddenSymbolByAddr(addr)[0]
		if hookingFunction.Owner == "system" {
			continue
		}
		functionName := "unknown"
		switch idx {
		case IterateShared:
			functionName = "iterate_shared"
		case Iterate:
			functionName = "iterate"
		}
		hookedFops = append(hookedFops, trace.HookedSymbolData{SymbolName: functionName, ModuleOwner: hookingFunction.Owner})
	}
	err = events.SetArgValue(event, hookedFopsPointersArgName, hookedFops)
	if err != nil {
		return err
	}
	return nil
}

// processTriggeredEvent processes a triggered event (e.g. print_syscall_table, print_net_seq_ops).
func (t *Tracee) processTriggeredEvent(event *trace.Event) error {
	// Initial event - no need to process
	if event.Timestamp == 0 {
		return nil
	}
	withInvokingContext, err := t.triggerContexts.Apply(*event)
	if err != nil {
		return errfmt.Errorf("failed to apply invoke context on %s event: %s", event.EventName, err)
	}
	// This was previously event = &withInvokingContext. However, if applied as such,
	// withInvokingContext will go out of policy and the reference will be moved back as such we
	// apply the value internally and not through a reference switch
	(*event) = withInvokingContext
	return nil
}

// processPrintSyscallTable processes a print_syscall_table event.
func (t *Tracee) processPrintMemDump(event *trace.Event) error {
	address, err := parse.ArgVal[uintptr](event.Args, "address")
	if err != nil || address == 0 {
		return errfmt.Errorf("error parsing print_mem_dump args: %v", err)
	}

	addressUint64 := uint64(address)
	symbol := t.getKernelSymbols().GetPotentiallyHiddenSymbolByAddr(addressUint64)[0]
	var utsName unix.Utsname
	arch := ""
	if err := unix.Uname(&utsName); err != nil {
		return errfmt.WrapError(err)
	}
	arch = string(bytes.TrimRight(utsName.Machine[:], "\x00"))
	err = events.SetArgValue(event, "arch", arch)
	if err != nil {
		return err
	}
	err = events.SetArgValue(event, "symbol_name", symbol.Name)
	if err != nil {
		return err
	}
	err = events.SetArgValue(event, "symbol_owner", symbol.Owner)
	if err != nil {
		return err
	}
	return nil
}

//
// Timing related functions
//

// normalizeTimeArg returns a processor function for some argument name
// which normalizes said event arg time from boot monotonic to epoch
func (t *Tracee) normalizeTimeArg(argNames ...string) func(event *trace.Event) error {
	return func(event *trace.Event) error {
		for _, argName := range argNames {
			arg := events.GetArg(event, argName)
			if arg == nil {
				return errfmt.Errorf("couldn't find argument %s of event %s", argName, event.EventName)
			}
			if arg.Value == nil {
				continue
			}

			argTime, ok := arg.Value.(uint64)
			if !ok {
				return errfmt.Errorf("argument %s of event %s is not uint64, it is %T", argName, event.EventName, arg.Value)
			}
			arg.Value = time.BootToEpochNS(argTime)
		}
		return nil
	}
}

// addHashArg calculate file hash (in a best-effort efficiency manner) and add it as an argument
func (t *Tracee) addHashArg(event *trace.Event, fileKey *filehash.Key) error {
	// Currently Tracee does not support hash calculation of memfd files
	if strings.HasPrefix(fileKey.Pathname(), "memfd") {
		return nil
	}

	hashArg := trace.Argument{
		ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
	}

	hash, err := t.fileHashes.Get(fileKey)
	if hash == "" {
		hashArg.Value = nil
	} else {
		hashArg.Value = hash
	}

	event.Args = append(event.Args, hashArg)
	event.ArgsNum++

	// Container FS unreachable can happen because of race condition on any system,
	// so there is no reason to return an error on it
	if errors.Is(err, containers.ErrContainerFSUnreachable) {
		logger.Debugw("failed to calculate hash", "error", err, "mount NS", event.MountNS)
		err = nil
	}

	return err
}

func (t *Tracee) processSharedObjectLoaded(event *trace.Event) error {
	filePath, err := parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		logger.Debugw("Error parsing argument", "error", err)
		return nil
	}
	fileCtime, err := parse.ArgVal[uint64](event.Args, "ctime")
	if err != nil {
		logger.Debugw("Error parsing argument", "error", err)
		return nil
	}
	dev, err := parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
	}
	ino, err := parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
	}

	containerId := event.Container.ID
	if containerId == "" {
		containerId = "host"
	}
	if t.config.Output.CalcHashes != config.CalcHashesNone {
		fileKey := filehash.NewKey(filePath, event.MountNS,
			filehash.WithDevice(dev),
			filehash.WithInode(ino, int64(fileCtime)),
			filehash.WithDigest(event.Container.ImageDigest),
		)

		return t.addHashArg(event, &fileKey)
	}

	return nil
}

//
// Context related functions
//

func (t *Tracee) removeContext(event *trace.Event) error {
	event.ThreadStartTime = 0
	event.ProcessorID = 0
	event.ProcessID = 0
	event.CgroupID = 0
	event.ThreadID = 0
	event.ParentProcessID = 0
	event.HostProcessID = 0
	event.HostThreadID = 0
	event.HostParentProcessID = 0
	event.UserID = 0
	event.MountNS = 0
	event.PIDNS = 0
	event.ProcessName = ""
	event.Executable = trace.File{}
	event.HostName = ""
	event.ContainerID = ""
	event.Container = trace.Container{}
	event.Kubernetes = trace.Kubernetes{}
	event.Syscall = ""
	event.StackAddresses = []uint64{}
	event.ContextFlags = trace.ContextFlags{}
	event.ThreadEntityId = 0
	event.ProcessEntityId = 0
	event.ParentEntityId = 0

	return nil
}

func (t *Tracee) removeIrrelevantContext(event *trace.Event) error {
	// Uprobe events are created in the context of tracee's process,
	// but that context is meaningless. Remove it.
	if event.ProcessID == os.Getpid() {
		return t.removeContext(event)
	}

	return nil
}
