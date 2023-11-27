package ebpf

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
	if t.config.Capture.Exec || t.config.Output.ExecHash {
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
					// capture (SchedProcessExec sets base capabilities to have cap.SYS_PTRACE set.
					// This is needed at this point because raising and dropping capabilities too
					// frequently would have a big performance impact)
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
					// if ExecHash is enabled, we need to make sure base ring has the needed
					// capabilities (cap.SYS_PTRACE), since it might not always have been enabled by
					// event capabilities requirements (there is no "exec hash" event) from
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

// processDoFinitModule handles a do_finit_module event and triggers other hooking detection logic.
func (t *Tracee) processDoInitModule(event *trace.Event) error {
	_, okSyscalls := t.eventsState[events.HookedSyscall]
	_, okSeqOps := t.eventsState[events.HookedSeqOps]
	_, okProcFops := t.eventsState[events.HookedProcFops]
	_, okMemDump := t.eventsState[events.PrintMemDump]

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
		if okSyscalls && expectedSyscallTableInit {
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
	}

	return nil
}

const (
	IterateShared int = iota
	Iterate
)

// processHookedProcFops processes a hooked_proc_fops event.
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

//
// Timing related functions
//

// normalizeEventCtxTimes normalizes the event context timings to be relative to tracee start time
// or current time in nanoseconds.
func (t *Tracee) normalizeEventCtxTimes(event *trace.Event) error {
	//
	// Currently, the timestamp received from the bpf code is of the monotonic clock.
	//
	// TODO: The monotonic clock doesn't take into account system sleep time.
	// Starting from kernel 5.7, we can get the timestamp relative to the system boot time
	// instead which is preferable.

	if t.config.Output.RelativeTime {
		// monotonic time since tracee started: timestamp - tracee starttime
		event.Timestamp = event.Timestamp - int(t.startTime)
		event.ThreadStartTime = event.ThreadStartTime - int(t.startTime)
	} else {
		// current ("wall") time: add boot time to timestamp
		event.Timestamp = event.Timestamp + int(t.bootTime)
		event.ThreadStartTime = event.ThreadStartTime + int(t.bootTime)
	}

	return nil
}

// getOrigEvtTimestamp returns the original timestamp of the event.
// To be used only when the event timestamp was normalized via normalizeEventCtxTimes.
func (t *Tracee) getOrigEvtTimestamp(event *trace.Event) int {
	if t.config.Output.RelativeTime {
		// if the time was normalized relative to tracee start time, add the start time back
		return event.Timestamp + int(t.startTime)
	}

	// if the time was normalized to "wall" time, subtract the boot time
	return event.Timestamp - int(t.bootTime)
}

// processSchedProcessFork processes a sched_process_fork event by normalizing the start time.
func (t *Tracee) processSchedProcessFork(event *trace.Event) error {
	return t.normalizeEventArgTime(event, "start_time")
}

// normalizeEventArgTime normalizes the event arg time to be relative to tracee start time or
// current time.
func (t *Tracee) normalizeEventArgTime(event *trace.Event, argName string) error {
	arg := events.GetArg(event, argName)
	if arg == nil {
		return errfmt.Errorf("couldn't find argument %s of event %s", argName, event.EventName)
	}
	argTime, ok := arg.Value.(uint64)
	if !ok {
		return errfmt.Errorf("argument %s of event %s is not of type uint64", argName, event.EventName)
	}
	if t.config.Output.RelativeTime {
		// monotonic time since tracee started: timestamp - tracee starttime
		arg.Value = argTime - t.startTime
	} else {
		// current ("wall") time: add boot time to timestamp
		arg.Value = argTime + t.bootTime
	}
	return nil
}
