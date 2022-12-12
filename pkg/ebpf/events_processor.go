package ebpf

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

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

func (t *Tracee) processEvent(event *trace.Event) error {
	eventId := events.ID(event.EventID)

	switch eventId {

	case events.VfsWrite, events.VfsWritev, events.KernelWrite:
		// capture written files
		if t.config.Capture.FileWrite {
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
		}

	case events.SchedProcessExec:
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

	case events.SchedProcessExit:
		if t.config.ProcessInfo {
			if t.config.Capture.NetPerProcess {
				pcapContext, _, err := t.getPcapContextFromTid(uint32(event.HostThreadID))
				if err == nil {
					go t.netExit(pcapContext)
				}
			}

			go t.deleteProcInfoDelayed(event.HostThreadID)
		}

	case events.SchedProcessFork:
		err := t.convertArgMonotonicToEpochTime(event, "start_time")
		if err != nil {
			return err
		}
		if t.config.ProcessInfo {
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
		}

	case events.CgroupMkdir:
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
			t.containers.RemoveFromBpfMap(t.bpfModule, cgroupId, hId)
		}

	case events.CgroupRmdir:
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

	// In case FinitModule and InitModule occurs, it means that a kernel module
	// was loaded and tracee needs to check if it hooked the syscall table and
	// seq_ops
	case events.DoInitModule:
		_, ok1 := t.events[events.HookedSyscalls]
		_, ok2 := t.events[events.HookedSeqOps]
		_, ok3 := t.events[events.HookedProcFops]
		if ok1 || ok2 || ok3 {
			err := t.updateKallsyms()
			if err != nil {
				return err
			}
			t.triggerSyscallsIntegrityCheck(*event)
			t.triggerSeqOpsIntegrityCheck(*event)
		}

	case events.HookedProcFops:
		const (
			addrWhiteList = "fops_addrs_whitelists"
		)
		fopsAddresses, err := parse.ArgVal[[]uint64](event, "hooked_fops_pointers")
		if err != nil || fopsAddresses == nil {
			return fmt.Errorf("error parsing hooked_proc_fops args: %w", err)
		}
		hookedFops := make([]trace.HookedSymbolData, 0)
		for idx, addr := range fopsAddresses {
			if addr == 0 {
				continue
			}
			inTextSeg, err := t.kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				return fmt.Errorf("error checking kernel address: %v", err)
			}
			if !inTextSeg {
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
			} else { // if no hooked data is found, mark the pointer as safe
				whitelistMap, err := t.bpfModule.GetMap(addrWhiteList)
				if err != nil {
					logger.Error("error getting hooked_proc_fops whitelist map", "error", err)
					continue
				}
				pair := [2]uint64{fopsAddresses[0], fopsAddresses[1]}
				slot := 1 // value to place in map
				whitelistMap.Update(unsafe.Pointer(&pair), unsafe.Pointer(&slot))
			}
		}
		event.Args[0].Value = hookedFops

	case events.PrintNetSeqOps, events.PrintSyscallTable:
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
	}

	return nil
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
