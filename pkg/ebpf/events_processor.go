package ebpf

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
)

func (t *Tracee) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
		// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
		// https://github.com/aquasecurity/libbpfgo/issues/122
		if lost > 0 {
			t.stats.LostEvCount.Increment(lost)
			logger.Warn(fmt.Sprintf("lost %d events", lost))
		}
	}
}

func (t *Tracee) deleteProcInfoDelayed(hostTid int) {
	// wait 5 seconds before deleting from the map - because there might events coming in the context of this process,
	// after we receive its sched_process_exit. this mainly happens from network events, because these events come from
	// the netChannel, and there might be a race condition between this channel and the eventsChannel.
	time.Sleep(time.Second * 5)
	t.procInfo.DeleteElement(hostTid)
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
			logger.Error("error processing event", "event", event.EventName, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

// RegisterEventProcessor registers a pipeline processing handler for an event
func (t *Tracee) RegisterEventProcessor(id events.ID, proc func(evt *trace.Event) error) error {
	if t.eventProcessor == nil {
		return fmt.Errorf("tracee not initalized yet")
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

	// no need to error check since we know the error is initalization related
	t.RegisterEventProcessor(events.VfsWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.VfsWritev, t.processWriteEvent)
	t.RegisterEventProcessor(events.KernelWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.SchedProcessExec, t.processSchedProcessExec)
	t.RegisterEventProcessor(events.SchedProcessExit, t.processSchedProcessExit)
	t.RegisterEventProcessor(events.SchedProcessFork, t.processSchedProcessFork)
	t.RegisterEventProcessor(events.CgroupMkdir, t.processCgroupMkdir)
	t.RegisterEventProcessor(events.CgroupRmdir, t.processCgroupRmdir)
	t.RegisterEventProcessor(events.DoInitModule, t.processDoInitModule)
	t.RegisterEventProcessor(events.HookedProcFops, t.processHookedProcFops)
	t.RegisterEventProcessor(events.PrintNetSeqOps, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.PrintSyscallTable, t.processTriggeredEvent)
}

func (t *Tracee) updateProfile(sourceFilePath string, executionTs uint64) {
	if pf, ok := t.profiledFiles[sourceFilePath]; !ok {
		t.profiledFiles[sourceFilePath] = profilerInfo{
			Times:            1,
			FirstExecutionTs: executionTs,
		}
	} else {
		pf.Times = pf.Times + 1              // bump execution count
		t.profiledFiles[sourceFilePath] = pf // update
	}
}

// convertArgMonotonicToEpochTime change time from monotonic relative time to time since epoch.
// Monotonic time is timestamp relative to the boot time (not including sleep time)
// Add the boot time to receive timestamp which is approximately relative to epoch.
func (t *Tracee) convertArgMonotonicToEpochTime(event *trace.Event, argName string) error {
	relTimeArg := events.GetArg(event, argName)
	if relTimeArg == nil {
		return fmt.Errorf("couldn't find argument %s of event %s", argName, event.EventName)
	}
	relTime, ok := relTimeArg.Value.(uint64)
	if !ok {
		return fmt.Errorf("argument %s of event %s is not of type uint64", argName, event.EventName)
	}
	relTimeArg.Value = relTime + t.bootTime
	return nil
}

func (t *Tracee) processWriteEvent(event *trace.Event) error {
	// only capture written files
	if !t.config.Capture.FileWrite {
		return nil
	}
	filePath, err := parse.ArgVal[string](event, "pathname")
	if err != nil {
		return fmt.Errorf("error parsing vfs_write args: %v", err)
	}
	// path should be absolute, except for e.g memfd_create files
	if filePath == "" || filePath[0] != '/' {
		return nil
	}
	dev, err := parse.ArgVal[uint32](event, "dev")
	if err != nil {
		return fmt.Errorf("error parsing vfs_write args: %v", err)
	}
	inode, err := parse.ArgVal[uint64](event, "inode")
	if err != nil {
		return fmt.Errorf("error parsing vfs_write args: %v", err)
	}

	// stop processing if write was already indexed
	containerId := event.ContainerID
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

func (t *Tracee) processSchedProcessExec(event *trace.Event) error {
	// update the process tree with correct command name
	if t.config.ProcessInfo {
		processData, err := t.procInfo.GetElement(event.HostProcessID)
		if err == nil {
			processData.Comm = event.ProcessName
			t.procInfo.UpdateElement(event.HostProcessID, processData)
		}
	}
	// cache this pid by it's mnt ns
	if event.ProcessID == 1 {
		t.pidsInMntns.ForceAddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	} else {
		t.pidsInMntns.AddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
	}
	// capture executed files
	if t.config.Capture.Exec || t.config.Output.ExecHash {
		filePath, err := parse.ArgVal[string](event, "pathname")
		if err != nil {
			return fmt.Errorf("error parsing sched_process_exec args: %v", err)
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
			sourceFileCtime, err := parse.ArgVal[uint64](event, "ctime")
			if err != nil {
				return fmt.Errorf("error parsing sched_process_exec args: %v", err)
			}
			castedSourceFileCtime := int64(sourceFileCtime)

			containerId := event.ContainerID
			if containerId == "" {
				containerId = "host"
			}
			capturedFileID := fmt.Sprintf("%s:%s", containerId, sourceFilePath)
			// capture exec'ed files ?
			if t.config.Capture.Exec {
				destinationDirPath := containerId
				if err := utils.MkdirAtExist(t.outDir, destinationDirPath, 0755); err != nil {
					return err
				}
				destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", event.Timestamp, filepath.Base(filePath)))
				// create an in-memory profile
				if t.config.Capture.Profile {
					t.updateProfile(fmt.Sprintf("%s:%d", filepath.Join(destinationDirPath, fmt.Sprintf("exec.%s", filepath.Base(filePath))), castedSourceFileCtime), uint64(event.Timestamp))
				}
				// don't capture same file twice unless it was modified
				lastCtime, ok := t.capturedFiles[capturedFileID]
				if !ok || lastCtime != castedSourceFileCtime {

					// capture (ring1)
					err = capabilities.GetInstance().Required(func() error {
						return utils.CopyRegularFileByRelativePath(
							sourceFilePath,
							t.outDir,
							destinationFilePath,
						)
					})
					if err != nil {
						return err
					}

					// mark this file as captured
					t.capturedFiles[capturedFileID] = castedSourceFileCtime
				}
			}
			// check exec'ed hash ?
			if t.config.Output.ExecHash {
				var hashInfoObj fileExecInfo
				var currentHash string
				hashInfoInterface, ok := t.fileHashes.Get(capturedFileID)
				if ok {
					hashInfoObj = hashInfoInterface.(fileExecInfo)
				}
				// check if cache can be used
				if ok && hashInfoObj.LastCtime == castedSourceFileCtime {
					currentHash = hashInfoObj.Hash
				} else {

					// ring1
					capabilities.GetInstance().Required(func() error {
						currentHash, err = computeFileHashAtPath(sourceFilePath)
						if err == nil {
							hashInfoObj = fileExecInfo{castedSourceFileCtime, currentHash}
							t.fileHashes.Add(capturedFileID, hashInfoObj)
						}
						return nil
					})

				}
				event.Args = append(event.Args, trace.Argument{
					ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"},
					Value:   currentHash,
				})
				event.ArgsNum += 1
			}
			if true { // so loop is conditionally terminated (#SA4044)
				break
			}
		}
		return err
	}
	return nil
}

func (t *Tracee) processSchedProcessExit(event *trace.Event) error {
	if !t.config.ProcessInfo {
		return nil
	}
	if t.config.Capture.NetPerProcess {
		pcapContext, _, err := t.getPcapContextFromTid(uint32(event.HostThreadID))
		if err == nil {
			go t.netExit(pcapContext)
		}
	}

	go t.deleteProcInfoDelayed(event.HostThreadID)
	return nil
}

func (t *Tracee) processSchedProcessFork(event *trace.Event) error {
	err := t.convertArgMonotonicToEpochTime(event, "start_time")
	if err != nil {
		return err
	}
	if !t.config.ProcessInfo {
		return nil
	}
	hostTid, err := parse.ArgVal[int32](event, "child_tid")
	if err != nil {
		return err
	}
	hostPid, err := parse.ArgVal[int32](event, "child_pid")
	if err != nil {
		return err
	}
	pid, err := parse.ArgVal[int32](event, "child_ns_pid")
	if err != nil {
		return err
	}
	ppid, err := parse.ArgVal[int32](event, "parent_ns_pid")
	if err != nil {
		return err
	}
	hostPpid, err := parse.ArgVal[int32](event, "parent_pid")
	if err != nil {
		return err
	}
	tid, err := parse.ArgVal[int32](event, "child_ns_tid")
	if err != nil {
		return err
	}
	startTime, err := parse.ArgVal[uint64](event, "start_time")
	if err != nil {
		return err
	}
	processData := procinfo.ProcessCtx{
		StartTime:   int(startTime),
		ContainerID: event.ContainerID,
		Pid:         uint32(pid),
		Tid:         uint32(tid),
		Ppid:        uint32(ppid),
		HostTid:     uint32(hostTid),
		HostPid:     uint32(hostPid),
		HostPpid:    uint32(hostPpid),
		Uid:         uint32(event.UserID),
		MntId:       uint32(event.MountNS),
		PidId:       uint32(event.PIDNS),
		Comm:        event.ProcessName,
	}
	t.procInfo.UpdateElement(int(hostTid), processData)
	return nil
}

func (t *Tracee) processCgroupMkdir(event *trace.Event) error {
	cgroupId, err := parse.ArgVal[uint64](event, "cgroup_id")
	if err != nil {
		return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
	}
	path, err := parse.ArgVal[string](event, "cgroup_path")
	if err != nil {
		return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
	}
	hId, err := parse.ArgVal[uint32](event, "hierarchy_id")
	if err != nil {
		return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
	}
	info, err := t.containers.CgroupMkdir(cgroupId, path, hId)
	if err == nil && info.Container.ContainerId == "" {
		// If cgroupId is from a regular cgroup directory, and not the
		// container base directory (from known runtimes), it should be
		// removed from the containers bpf map.
		err = t.containers.RemoveFromBpfMap(t.bpfModule, cgroupId, hId)
	}
	return err
}

func (t *Tracee) processCgroupRmdir(event *trace.Event) error {
	cgroupId, err := parse.ArgVal[uint64](event, "cgroup_id")
	if err != nil {
		return fmt.Errorf("error parsing cgroup_rmdir args: %w", err)
	}

	if t.config.Capture.NetPerContainer {
		if info := t.containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			pcapContext := t.getContainerPcapContext(info.Container.ContainerId)
			go t.netExit(pcapContext)
		}
	}

	hId, err := parse.ArgVal[uint32](event, "hierarchy_id")
	if err != nil {
		return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
	}
	t.containers.CgroupRemove(cgroupId, hId)
	return nil
}

// In case FinitModule and InitModule occurs, it means that a kernel module
// was loaded and tracee needs to check if it hooked the syscall table and
// seq_ops
func (t *Tracee) processDoInitModule(event *trace.Event) error {
	_, ok1 := t.events[events.HookedSyscalls]
	_, ok2 := t.events[events.HookedSeqOps]
	_, ok3 := t.events[events.HookedProcFops]
	if ok1 || ok2 || ok3 {
		err := t.UpdateKallsyms()
		if err != nil {
			return err
		}
		t.triggerSyscallsIntegrityCheck(*event)
		t.triggerSeqOpsIntegrityCheck(*event)
	}
	return nil
}

func (t *Tracee) processHookedProcFops(event *trace.Event) error {
	fopsAddresses, err := parse.ArgVal[[]uint64](event, "hooked_fops_pointers")
	if err != nil || fopsAddresses == nil {
		return fmt.Errorf("error parsing hooked_proc_fops args: %w", err)
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
		return fmt.Errorf("failed to apply invoke context on %s event: %s", event.EventName, err)
	}
	// This was previously event = &withInvokingContext. However, if applied
	// as such, withInvokingContext will go out of scope and the reference
	// will be moved back as such we apply the value internally and not
	// through a referene switch
	(*event) = withInvokingContext
	return nil
}
