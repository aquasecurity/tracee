package ebpf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/pkg/utils"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/types/trace"
)

func MatchFilter(filters []string, argValStr string) bool {
	for _, f := range filters {
		prefixCheck := f[len(f)-1] == '*'
		if prefixCheck {
			f = f[0 : len(f)-1]
		}
		suffixCheck := f[0] == '*'
		if suffixCheck {
			f = f[1:]
		}
		if argValStr == f ||
			(prefixCheck && !suffixCheck && strings.HasPrefix(argValStr, f)) ||
			(suffixCheck && !prefixCheck && strings.HasSuffix(argValStr, f)) ||
			(prefixCheck && suffixCheck && strings.Contains(argValStr, f)) {
			return true
		}
	}
	return false
}

func (t *Tracee) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
		// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
		// https://github.com/aquasecurity/libbpfgo/issues/122
		if lost > 0 {
			t.stats.LostEvCount.Increment(int(lost))
			t.config.ChanErrors <- fmt.Errorf("lost %d events", lost)
		}
	}
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *Tracee) shouldProcessEvent(ctx *bufferdecoder.Context, args []trace.Argument) bool {
	if t.config.Filter.RetFilter.Enabled {
		if filter, ok := t.config.Filter.RetFilter.Filters[ctx.EventID]; ok {
			retVal := ctx.Retval
			match := false
			for _, f := range filter.Equal {
				if retVal == f {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if retVal == f {
					return false
				}
			}
			if (filter.Greater != GreaterNotSetInt) && retVal <= filter.Greater {
				return false
			}
			if (filter.Less != LessNotSetInt) && retVal >= filter.Less {
				return false
			}
		}
	}

	if t.config.Filter.ArgFilter.Enabled {
		for argName, filter := range t.config.Filter.ArgFilter.Filters[events.ID(ctx.EventID)] {
			var argVal interface{}
			ok := false
			for _, arg := range args {
				if arg.Name == argName {
					argVal = arg.Value
					ok = true
				}
			}
			if !ok {
				continue
			}
			// TODO: use type assertion instead of string conversion
			argValStr := fmt.Sprint(argVal)
			match := MatchFilter(filter.Equal, argValStr)
			if !match && len(filter.Equal) > 0 {
				return false
			}
			matchExclude := MatchFilter(filter.NotEqual, argValStr)
			if matchExclude {
				return false
			}
		}
	}

	return true
}

func (t *Tracee) deleteProcInfoDelayed(hostTid int) {
	// wait 5 seconds before deleting from the map - because there might events coming in the context of this process,
	// after we receive its sched_process_exit. this mainly happens from network events, because these events come from
	// the netChannel, and there might be a race condition between this channel and the eventsChannel.
	time.Sleep(time.Second * 5)
	t.procInfo.DeleteElement(hostTid)
}

const (
	StructFopsPointer int = iota
	IterateShared
	Iterate
)

func (t *Tracee) processEvent(event *trace.Event) error {
	eventId := events.ID(event.EventID)
	switch eventId {

	case events.VfsWrite, events.VfsWritev, events.KernelWrite:
		//capture written files
		if t.config.Capture.FileWrite {
			filePath, err := parse.ArgStringVal(event, "pathname")
			if err != nil {
				return fmt.Errorf("error parsing vfs_write args: %v", err)
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}
			dev, err := parse.ArgUint32Val(event, "dev")
			if err != nil {
				return fmt.Errorf("error parsing vfs_write args: %v", err)
			}
			inode, err := parse.ArgUint64Val(event, "inode")
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
		//update the process tree with correct comm name
		if t.config.ProcessInfo {
			processData, err := t.procInfo.GetElement(event.HostProcessID)
			if err == nil {
				processData.Comm = event.ProcessName
				t.procInfo.UpdateElement(event.HostProcessID, processData)
			}
		}

		//cache this pid by it's mnt ns
		if event.ProcessID == 1 {
			t.pidsInMntns.ForceAddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
		} else {
			t.pidsInMntns.AddBucketItem(uint32(event.MountNS), uint32(event.HostProcessID))
		}
		//capture executed files
		if t.config.Capture.Exec || t.config.Output.ExecHash {
			filePath, err := parse.ArgStringVal(event, "pathname")
			if err != nil {
				return fmt.Errorf("error parsing sched_process_exec args: %v", err)
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}

			// try to access the root fs via another process in the same mount namespace (since the current process might have already died)
			pids := t.pidsInMntns.GetBucket(uint32(event.MountNS))
			for _, pid := range pids { // will break on success
				err = nil
				sourceFilePath := fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pid)), filePath)
				sourceFileCtime, err := parse.ArgUint64Val(event, "ctime")
				if err != nil {
					return fmt.Errorf("error parsing sched_process_exec args: %v", err)
				}
				castedSourceFileCtime := int64(sourceFileCtime)

				containerId := event.ContainerID
				if containerId == "" {
					containerId = "host"
				}
				capturedFileID := fmt.Sprintf("%s:%s", containerId, sourceFilePath)
				if t.config.Capture.Exec {
					destinationDirPath := filepath.Join(t.config.Capture.OutputPath, containerId)
					if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
						return err
					}
					destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", event.Timestamp, filepath.Base(filePath)))

					// create an in-memory profile
					if t.config.Capture.Profile {
						t.updateProfile(fmt.Sprintf("%s:%d", filepath.Join(destinationDirPath, fmt.Sprintf("exec.%s", filepath.Base(filePath))), castedSourceFileCtime), uint64(event.Timestamp))
					}

					//don't capture same file twice unless it was modified
					lastCtime, ok := t.capturedFiles[capturedFileID]
					if !ok || lastCtime != castedSourceFileCtime {
						//capture
						err = CopyFileByPath(sourceFilePath, destinationFilePath)
						if err != nil {
							return err
						}
						//mark this file as captured
						t.capturedFiles[capturedFileID] = castedSourceFileCtime
					}
				}

				if t.config.Output.ExecHash {
					var hashInfoObj fileExecInfo
					var currentHash string
					hashInfoInterface, ok := t.fileHashes.Get(capturedFileID)

					// cast to fileExecInfo
					if ok {
						hashInfoObj = hashInfoInterface.(fileExecInfo)
					}
					// Check if cache can be used
					if ok && hashInfoObj.LastCtime == castedSourceFileCtime {
						currentHash = hashInfoObj.Hash
					} else {
						currentHash, err = computeFileHash(sourceFilePath)
						if err == nil {
							hashInfoObj = fileExecInfo{castedSourceFileCtime, currentHash}
							t.fileHashes.Add(capturedFileID, hashInfoObj)
						}
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
		if t.config.ProcessInfo {
			hostTid, err := parse.ArgInt32Val(event, "child_tid")
			if err != nil {
				return err
			}
			hostPid, err := parse.ArgInt32Val(event, "child_pid")
			if err != nil {
				return err
			}
			pid, err := parse.ArgInt32Val(event, "child_ns_pid")
			if err != nil {
				return err
			}
			ppid, err := parse.ArgInt32Val(event, "parent_ns_pid")
			if err != nil {
				return err
			}
			hostPpid, err := parse.ArgInt32Val(event, "parent_pid")
			if err != nil {
				return err
			}
			tid, err := parse.ArgInt32Val(event, "child_ns_tid")
			if err != nil {
				return err
			}
			startTime, err := parse.ArgUint64Val(event, "start_time")
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
		cgroupId, err := parse.ArgUint64Val(event, "cgroup_id")
		if err != nil {
			return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
		}
		path, err := parse.ArgStringVal(event, "cgroup_path")
		if err != nil {
			return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
		}
		hId, err := parse.ArgUint32Val(event, "hierarchy_id")
		if err != nil {
			return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
		}
		info, err := t.containers.CgroupMkdir(cgroupId, path, hId)
		if err == nil && info.Container.ContainerId == "" {
			// If cgroupId is from a regular cgroup directory, and not the
			// container base directory (from known runtimes), it should be
			// removed from the "containers_map".
			t.containers.RemoveFromBpfMap(t.bpfModule, cgroupId, hId, "containers_map")
		}

	case events.CgroupRmdir:
		cgroupId, err := parse.ArgUint64Val(event, "cgroup_id")
		if err != nil {
			return fmt.Errorf("error parsing cgroup_rmdir args: %w", err)
		}

		if t.config.Capture.NetPerContainer {
			if info := t.containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
				pcapContext := t.getContainerPcapContext(info.Container.ContainerId)
				go t.netExit(pcapContext)
			}
		}

		hId, err := parse.ArgUint32Val(event, "hierarchy_id")
		if err != nil {
			return fmt.Errorf("error parsing cgroup_mkdir args: %w", err)
		}
		t.containers.CgroupRemove(cgroupId, hId)

	// in case FinitModule and InitModule occurs it means that a kernel module was loaded
	// and we will want to check if it hooked the syscall table and seq_ops
	case events.InitModule, events.FinitModule:
		err := t.updateKallsyms()
		if err != nil {
			return err
		}
		err = t.invokeIoctlTriggeredEvents(IoctlFetchSyscalls | IoctlHookedSeqOps)
		if err != nil {
			return err
		}

	case events.HookedProcFops:
		fopsAddresses, err := parse.ArgUlongArrVal(event, "hooked_fops_pointers")
		if err != nil || fopsAddresses == nil {
			return fmt.Errorf("error parsing hooked_proc_fops args: %w", err)
		}
		hookedFops := make([]trace.HookedSymbolData, 0)
		for idx, addr := range fopsAddresses {
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
				case StructFopsPointer:
					functionName = "struct file_operations pointer"
				case IterateShared:
					functionName = "iterate_shared"
				case Iterate:
					functionName = "iterate"
				}
				hookedFops = append(hookedFops, trace.HookedSymbolData{SymbolName: functionName, ModuleOwner: hookingFunction.Owner})
			}
		}
		event.Args[0].Value = hookedFops
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

// CopyFileByPath copies a file from src to dst
func CopyFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}
