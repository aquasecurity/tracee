package procinfo

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/types/trace"
)

type ProcessCtx struct {
	StartTime   int // start time of the thread
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
	Comm        string
}

type ProcInfo struct {
	procInfoMap map[int]ProcessCtx
	mtx         sync.RWMutex // protecting both update and delete entries
}

func (p *ProcInfo) UpdateElement(hostTid int, ctx ProcessCtx) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.procInfoMap[hostTid] = ctx
}

func (p *ProcInfo) DeleteElement(hostTid int) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	delete(p.procInfoMap, hostTid)
}

func (p *ProcInfo) GetElement(hostTid int) (ProcessCtx, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	processCtx, ok := p.procInfoMap[hostTid]
	if !ok {
		return ProcessCtx{}, fmt.Errorf("no such a key: %v", hostTid)
	}
	return processCtx, nil
}

func (ctx *ProcessCtx) GetEventByProcessCtx() trace.Event {
	return trace.Event{
		ContainerID:         ctx.ContainerID,
		ProcessID:           int(ctx.Pid),
		ThreadID:            int(ctx.Tid),
		ParentProcessID:     int(ctx.Ppid),
		HostProcessID:       int(ctx.HostPid),
		HostThreadID:        int(ctx.HostTid),
		HostParentProcessID: int(ctx.HostPpid),
		UserID:              int(ctx.Uid),
		MountNS:             int(ctx.MntId),
		PIDNS:               int(ctx.PidId),
	}
}

func ParseProcessContext(ctx []byte, containers *containers.Containers) (ProcessCtx, error) {
	var procCtx = ProcessCtx{}
	const ctxSize = 52
	if len(ctx) < ctxSize {
		return procCtx, fmt.Errorf("can't read process context: buffer too short")
	}
	procCtx.StartTime = int(binary.LittleEndian.Uint64(ctx[0:8]))
	cgroupId := binary.LittleEndian.Uint64(ctx[8:16])
	procCtx.ContainerID = containers.GetCgroupInfo(cgroupId).Container.ContainerId
	procCtx.Pid = binary.LittleEndian.Uint32(ctx[16:20])
	procCtx.Tid = binary.LittleEndian.Uint32(ctx[20:24])
	procCtx.Ppid = binary.LittleEndian.Uint32(ctx[24:28])
	procCtx.HostTid = binary.LittleEndian.Uint32(ctx[28:32])
	procCtx.HostPid = binary.LittleEndian.Uint32(ctx[32:36])
	procCtx.HostPpid = binary.LittleEndian.Uint32(ctx[36:40])
	procCtx.Uid = binary.LittleEndian.Uint32(ctx[40:44])
	procCtx.MntId = binary.LittleEndian.Uint32(ctx[44:48])
	procCtx.PidId = binary.LittleEndian.Uint32(ctx[48:ctxSize])
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
	var processName string
	processVals := make(map[string]uint32)
	for _, line := range strings.Split(string(status), "\n") {
		lineFields := strings.Split(line, ":")
		if len(lineFields) > 1 {
			valFields := strings.Fields(lineFields[1])
			if len(valFields) > 0 {
				if lineFields[0] == "Name" {
					processName = valFields[0]
					continue
				}
				val, err := strconv.ParseUint(strings.TrimSpace(valFields[0]), 10, 32)
				if err != nil {
					continue
				}
				processVals[lineFields[0]] = uint32(val)
			}

		}
	}

	var err error
	var process ProcessCtx
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
	process.Comm = processName
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
func NewProcessInfo() (*ProcInfo, error) {
	p := ProcInfo{make(map[int]ProcessCtx), sync.RWMutex{}}
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()
	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	// iterate over each pid
	for _, procEntry := range entries {
		pid, err := strconv.ParseUint(procEntry, 10, 32)
		if err != nil {
			continue
		}

		taskDir, err := os.Open(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			continue
		}
		processTasks, err := taskDir.Readdirnames(-1)
		if err != nil {
			continue
		}
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
			p.UpdateElement(int(processStatus.HostTid), processStatus)
		}
	}
	return &p, nil
}
