package tracee

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/internal/bufferdecoder"
)

type ProcessCtx struct {
	StartTime   int
	ContainerID string
	Pid         uint32
	Tid         uint32
	Ppid        uint32
	HostTid     uint32
	HostPid     uint32
	HostPpid    uint32
	Uid         uint32
	MntId       uint32
	PidId       uint32
}

type ProcessTree struct {
	processTreeMap map[int]ProcessCtx
}

func (t *Tracee) ParseProcessContext(ctx []byte) (ProcessCtx, error) {
	var procCtx = ProcessCtx{}
	procCtx.StartTime = int(binary.LittleEndian.Uint64(ctx[0:8]))
	cgroupId := binary.LittleEndian.Uint64(ctx[8:16])
	procCtx.ContainerID = t.containers.GetCgroupInfo(cgroupId).ContainerId
	decoder := bufferdecoder.New(ctx[16:]) // this is the offset after the cgroup and startTime in the ctx byte array
	var errs []error
	errs = append(errs, decoder.DecodeUint32(&procCtx.Pid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.Tid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.Ppid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.HostTid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.HostPid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.HostPpid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.Uid))
	errs = append(errs, decoder.DecodeUint32(&procCtx.MntId))
	errs = append(errs, decoder.DecodeUint32(&procCtx.PidId))
	for _, e := range errs {
		if e != nil {
			return procCtx, e
		}
	}
	return procCtx, nil
}

//returns the file creation time
//Note: this is not the real process start time because it's based on the file creation time, but it is a close approximation
func getFileCtime(path string) (int, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat_t := fileInfo.Sys().(*syscall.Stat_t)
	ts := stat_t.Ctim
	return int(ts.Sec)*int(time.Second) + int(ts.Nsec)*int(time.Nanosecond), nil
}

//parse the status file of a process or given task and returns process context struct
func parseProcStatus(status []byte, taskStatusPath string) (ProcessCtx, error) {
	var process ProcessCtx
	processVals := make(map[string]uint32)
	for _, line := range strings.Split(string(status), "\n") {
		lineFields := strings.Split(line, ":")
		if len(lineFields) > 1 {
			valFields := strings.Fields(lineFields[1])
			if len(valFields) > 0 {
				val, err := strconv.ParseUint(strings.TrimSpace(valFields[0]), 10, 32)
				if err != nil {
					continue
				}
				processVals[lineFields[0]] = uint32(val)
			}

		}
	}

	var err error
	process.StartTime, err = getFileCtime(taskStatusPath)
	if err != nil {
		return process, err
	}
	process.HostPid = processVals["Tgid"]
	process.HostTid = processVals["Pid"]
	process.HostPpid = processVals["PPid"]
	process.Uid = processVals["Uid"]
	process.Pid = processVals["NStgid"]
	process.Tid = processVals["NSpid"]
	process.Ppid = processVals["NSpgid"]
	process.MntId, process.PidId, err = getNsIdData(taskStatusPath)
	if err != nil {
		return process, err
	}
	return process, nil
}

//gets the namespace data for the process Context struct by parsing the /proc/<Pid>/task directory
func getNsIdData(taskStatusPath string) (uint32, uint32, error) {
	path := fmt.Sprintf("%s/ns/mnt", taskStatusPath[:len(taskStatusPath)-7])
	processMntId, err := os.Readlink(path)
	if err != nil {
		return 0, 0, err
	}

	processMntId = strings.TrimSuffix(processMntId, "]")
	processMntId = strings.TrimPrefix(processMntId, "mnt:[")
	mntId, err := strconv.ParseUint(processMntId, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	path = fmt.Sprintf("%s/ns/pid", taskStatusPath[:len(taskStatusPath)-7])
	processPidId, err := os.Readlink(path)
	if err != nil {
		return 0, 0, err
	}
	processPidId = strings.TrimSuffix(processPidId, "]")
	processPidId = strings.TrimPrefix(processPidId, "pid:[")
	pidId, err := strconv.ParseUint(processPidId, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(mntId), uint32(pidId), nil
}

//initialize new process-tree
func NewProcessTree() (*ProcessTree, error) {
	p := ProcessTree{make(map[int]ProcessCtx)}
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()
	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	// Iterate over each pid
	for _, procEntry := range entries {
		pid, err := strconv.ParseUint(procEntry, 10, 32)
		if err != nil {
			continue
		}
		taskDir, err := os.Open(fmt.Sprintf("/proc/%d/task", pid))
		processTasks, err := taskDir.Readdirnames(-1)
		for _, task := range processTasks {
			taskDir := fmt.Sprintf("/proc/%d/task/%v", pid, task)
			taskStatus := fmt.Sprintf("/proc/%d/task/%v/status", pid, task)
			data, err := ioutil.ReadFile(taskStatus)
			if err != nil {
				// process might have exited - ignore this task
				continue
			}
			processStatus, err := parseProcStatus(data, taskStatus)
			if err != nil {
				continue
			}
			containerId, err := containers.GetContainerIdFromTaskDir(taskDir)
			if err != nil {
				continue
			}
			processStatus.ContainerID = containerId
			p.processTreeMap[int(processStatus.HostTid)] = processStatus
		}
	}
	return &p, nil
}
