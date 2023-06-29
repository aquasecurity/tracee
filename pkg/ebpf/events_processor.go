package ebpf

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	// initializing kernelReadFileTypes once at init.
	kernelReadFileTypes map[int32]trace.KernelReadType
	// exec hash might add capabilities to base ring
	onceExecHash sync.Once
)

func init() {
	initKernelReadFileTypes()
}

func (t *Tracee) processLostEvents() {
	logger.Debugw("Starting processLostEvents goroutine")
	defer logger.Debugw("Stopped processLostEvents goroutine")

	for {
		select {
		case lost := <-t.lostEvChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				if err := t.stats.LostEvCount.Increase(lost); err != nil {
					logger.Errorw("Incrementing lost event count", "error", err)
				}
				logger.Warnw(fmt.Sprintf("Lost %d events", lost))
			}
		// Since this is an end-state goroutine, it should be terminated only when Tracee done channel is closed.
		case <-t.done:
			return
		}
	}
}

const (
	IterateShared int = iota
	Iterate
)

func (t *Tracee) processEvent(event *trace.Event) []error {
	eventId := events.ID(event.EventID)
	processors := t.eventProcessor[eventId]
	errs := []error{}
	for _, procFunc := range processors {
		err := procFunc(event)
		if err != nil {
			logger.Errorw("Error processing event", "event", event.EventName, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

// RegisterEventProcessor registers a pipeline processing handler for an event
func (t *Tracee) RegisterEventProcessor(id events.ID, proc func(evt *trace.Event) error) error {
	if t.eventProcessor == nil {
		return errfmt.Errorf("tracee not initialized yet")
	}
	if t.eventProcessor[id] == nil {
		t.eventProcessor[id] = make([]func(evt *trace.Event) error, 0)
	}
	t.eventProcessor[id] = append(t.eventProcessor[id], proc)
	return nil
}

// registerEventProcessors registers tracee's internal default event processors
func (t *Tracee) registerEventProcessors() {
	if t.eventProcessor == nil {
		t.eventProcessor = make(map[events.ID][]func(evt *trace.Event) error)
	}

	// no need to error check since we know the error is initialization related
	t.RegisterEventProcessor(events.VfsWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.VfsWritev, t.processWriteEvent)
	t.RegisterEventProcessor(events.KernelWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.SchedProcessExec, t.processSchedProcessExec)
	t.RegisterEventProcessor(events.SchedProcessFork, t.processSchedProcessFork)
	t.RegisterEventProcessor(events.DoInitModule, t.processDoInitModule)
	t.RegisterEventProcessor(events.HookedProcFops, t.processHookedProcFops)
	t.RegisterEventProcessor(events.PrintNetSeqOps, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.PrintSyscallTable, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.SecurityKernelReadFile, processKernelReadFile)
	t.RegisterEventProcessor(events.SecurityPostReadFile, processKernelReadFile)
	t.RegisterEventProcessor(events.PrintMemDump, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.PrintMemDump, t.processPrintMemDump)
}

// convertArgMonotonicToEpochTime change time from monotonic relative time to time since epoch.
// Monotonic time is timestamp relative to the boot time (not including sleep time)
// Add the boot time to receive timestamp which is approximately relative to epoch.
func (t *Tracee) convertArgMonotonicToEpochTime(event *trace.Event, argName string) error {
	relTimeArg := events.GetArg(event, argName)
	if relTimeArg == nil {
		return errfmt.Errorf("couldn't find argument %s of event %s", argName, event.EventName)
	}
	relTime, ok := relTimeArg.Value.(uint64)
	if !ok {
		return errfmt.Errorf("argument %s of event %s is not of type uint64", argName, event.EventName)
	}
	relTimeArg.Value = relTime + t.bootTime
	return nil
}

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

func (t *Tracee) processSchedProcessExec(event *trace.Event) error {
	// cache this pid by it's mnt ns
	if event.ProcessID == 1 {
		t.pidsInMntns.ForceAddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	} else {
		t.pidsInMntns.AddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	}
	// capture executed files
	if t.config.Capture.Exec || t.config.Output.ExecHash {
		filePath, err := parse.ArgVal[string](event.Args, "pathname")
		if err != nil {
			return errfmt.Errorf("error parsing sched_process_exec args: %v", err)
		}
		// Should be absolute path, except for e.g memfd_create files
		if filePath == "" || filePath[0] != '/' {
			return nil
		}
		// try to access the root fs via another process in the same mount
		// namespace (as the process from the current event might have
		// already died)
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
			capturedFileID := fmt.Sprintf("%s:%s", containerId, sourceFilePath)
			// capture exec'ed files ?
			if t.config.Capture.Exec {
				destinationDirPath := containerId
				if err := utils.MkdirAtExist(t.OutDir, destinationDirPath, 0755); err != nil {
					return errfmt.WrapError(err)
				}
				destinationFilePath := filepath.Join(
					destinationDirPath,
					fmt.Sprintf("exec.%d.%s", event.Timestamp, filepath.Base(filePath)),
				)
				// don't capture same file twice unless it was modified
				lastCtime, ok := t.capturedFiles[capturedFileID]
				if !ok || lastCtime != castedSourceFileCtime {
					// capture (SchedProcessExec sets base capabilities to have
					// cap.SYS_PTRACE set. This is needed at this point because
					// raising and dropping capabilities too frequently would
					// have a big performance impact)
					err := utils.CopyRegularFileByRelativePath(
						sourceFilePath,
						t.OutDir,
						destinationFilePath,
					)
					if err != nil {
						return errfmt.WrapError(err)
					}
					// mark this file as captured
					t.capturedFiles[capturedFileID] = castedSourceFileCtime
				}
			}
			// check exec'ed hash ?
			if t.config.Output.ExecHash {
				var hashInfoObj fileExecInfo
				var currentHash string
				hashInfoObj, ok := t.fileHashes.Get(capturedFileID)
				// check if cache can be used
				if ok && hashInfoObj.LastCtime == castedSourceFileCtime {
					currentHash = hashInfoObj.Hash
				} else {
					// if ExecHash is enabled, we need to make sure base ring
					// has the needed capabilities (cap.SYS_PTRACE), since it
					// might not always have been enabled by event capabilities
					// requirements (there is no "exec hash" event) from
					// SchedProcessExec event.
					onceExecHash.Do(func() {
						err = capabilities.GetInstance().BaseRingAdd(cap.SYS_PTRACE)
						if err != nil {
							logger.Errorw("error adding cap.SYS_PTRACE to base ring", "error", err)
						}
					})
					currentHash, err = computeFileHashAtPath(sourceFilePath)
					if err == nil {
						hashInfoObj = fileExecInfo{castedSourceFileCtime, currentHash}
						t.fileHashes.Add(capturedFileID, hashInfoObj)
					}
				}
				event.Args = append(event.Args, trace.Argument{
					ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
					Value:   currentHash,
				})
				event.ArgsNum++
			}
			if true { // so loop is conditionally terminated (#SA4044)
				break
			}
		}
		return errfmt.WrapError(err)
	}
	return nil
}

func (t *Tracee) processSchedProcessFork(event *trace.Event) error {
	return t.convertArgMonotonicToEpochTime(event, "start_time")
}

// In case FinitModule and InitModule occurs, it means that a kernel module
// was loaded and tracee needs to check if it hooked the syscall table and
// seq_ops
func (t *Tracee) processDoInitModule(event *trace.Event) error {
	_, okSyscalls := t.events[events.HookedSyscalls]
	_, okSeqOps := t.events[events.HookedSeqOps]
	_, okProcFops := t.events[events.HookedProcFops]
	_, okMemDump := t.events[events.PrintMemDump]

	if okSyscalls || okSeqOps || okProcFops || okMemDump {
		err := capabilities.GetInstance().EBPF(
			func() error {
				return t.UpdateKallsyms()
			},
		)
		if err != nil {
			return errfmt.WrapError(err)
		}
		if err != nil {
			return errfmt.WrapError(err)
		}
		if okSyscalls {
			err = t.triggerSyscallsIntegrityCheck(*event)
			if err != nil {
				logger.Warnw("hooked_syscalls returned an error", "error", err)
			}
		}
		if okSeqOps {
			t.triggerSeqOpsIntegrityCheck(*event)
		}
		if okMemDump {
			err := t.triggerMemDump(*event)
			if err != nil {
				logger.Warnw("Memory dump", "error", err)
			}
		}
	}

	return nil
}

func (t *Tracee) processHookedProcFops(event *trace.Event) error {
	fopsAddresses, err := parse.ArgVal[[]uint64](event.Args, "hooked_fops_pointers")
	if err != nil || fopsAddresses == nil {
		return errfmt.Errorf("error parsing hooked_proc_fops args: %v", err)
	}
	hookedFops := make([]trace.HookedSymbolData, 0)
	for idx, addr := range fopsAddresses {
		if addr == 0 { // address is in text segment, marked as 0
			continue
		}
		hookingFunction := utils.ParseSymbol(addr, t.kernelSymbols)
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
	event.Args[0].Value = hookedFops
	return nil
}

func (t *Tracee) processTriggeredEvent(event *trace.Event) error {
	// Initial event - no need to process
	if event.Timestamp == 0 {
		return nil
	}
	withInvokingContext, err := t.triggerContexts.Apply(*event)
	if err != nil {
		return errfmt.Errorf("failed to apply invoke context on %s event: %s", event.EventName, err)
	}
	// This was previously event = &withInvokingContext. However, if applied
	// as such, withInvokingContext will go out of policy and the reference
	// will be moved back as such we apply the value internally and not
	// through a reference switch
	(*event) = withInvokingContext
	return nil
}

func initKernelReadFileTypes() {
	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return
	}

	kernel593ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.3")
	if err != nil {
		return
	}
	kernel570ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.7.0")
	if err != nil {
		return
	}
	kernel592ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.2")
	if err != nil {
		return
	}
	kernel5818ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.8.18")
	if err != nil {
		return
	}
	kernel4180ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("4.18.0")
	if err != nil {
		return
	}

	if kernel593ComparedToRunningKernel == helpers.KernelVersionOlder {
		// running kernel version: >=5.9.3
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadKernelModule,
			3: trace.KernelReadKExecImage,
			4: trace.KernelReadKExecInitRAMFS,
			5: trace.KernelReadSecurityPolicy,
			6: trace.KernelReadx509Certificate,
		}
	} else if kernel570ComparedToRunningKernel == helpers.KernelVersionOlder /* Running kernel is newer than 5.7.0 */ &&
		kernel592ComparedToRunningKernel != helpers.KernelVersionOlder /* Running kernel is equal or older than 5.9.2*/ &&
		kernel5818ComparedToRunningKernel != helpers.KernelVersionEqual /* Running kernel is not 5.8.18 */ {
		// running kernel version: >=5.7 && <=5.9.2 && !=5.8.18
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadFirmware,
			3: trace.KernelReadFirmware,
			4: trace.KernelReadKernelModule,
			5: trace.KernelReadKExecImage,
			6: trace.KernelReadKExecInitRAMFS,
			7: trace.KernelReadSecurityPolicy,
			8: trace.KernelReadx509Certificate,
		}
	} else if kernel5818ComparedToRunningKernel == helpers.KernelVersionEqual /* Running kernel is 5.8.18 */ ||
		(kernel570ComparedToRunningKernel == helpers.KernelVersionNewer && /* Running kernel is older than 5.7.0 */
			kernel4180ComparedToRunningKernel != helpers.KernelVersionOlder) /* Running kernel is 4.18 or newer */ {
		// running kernel version: ==5.8.18 || (<5.7 && >=4.18)
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadFirmware,
			3: trace.KernelReadKernelModule,
			4: trace.KernelReadKExecImage,
			5: trace.KernelReadKExecInitRAMFS,
			6: trace.KernelReadSecurityPolicy,
			7: trace.KernelReadx509Certificate,
		}
	}
}

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

func (t *Tracee) processPrintMemDump(event *trace.Event) error {
	address, err := parse.ArgVal[uintptr](event.Args, "address")
	if err != nil || address == 0 {
		return errfmt.Errorf("error parsing print_mem_dump args: %v", err)
	}

	addressUint64 := uint64(address)
	symbol := utils.ParseSymbol(addressUint64, t.kernelSymbols)
	var utsName unix.Utsname
	arch := ""
	if err := unix.Uname(&utsName); err != nil {
		return errfmt.WrapError(err)
	}
	arch = string(bytes.TrimRight(utsName.Machine[:], "\x00"))
	event.Args[4].Value = arch
	event.Args[5].Value = symbol.Name
	event.Args[6].Value = symbol.Owner
	return nil
}
