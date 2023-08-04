package controlplane

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

const pollTimeout int = 300 // from tracee.go (move to a consts package?)

// Control Plane probe handles
const (
	cgroupMkdirControlProbe probes.Handle = iota
	cgroupRmdirControlProbe
)

// These events are needed for some of the control plane events. At the eBPF side, they also submit
// events in the control plane perfbuffer. There isn't a need to set EventState for them (to
// configure Submit to a policy number), but there IS a need for dealing with their dependencies:
// making sure their probes are attached, make sure their dependencies are satisfied, make sure
// their tailCalls are indexed, etc.
var CoreEventsNeeded = []events.ID{
	events.SchedProcessFork,
	events.SchedProcessExec,
	events.SchedProcessExit,
}

type Controller struct {
	ctx               context.Context
	signalChan        chan []byte
	lostSignalChan    chan uint64
	bpfModule         *libbpfgo.Module
	controlProbeGroup *probes.ProbeGroup
	signalBuffer      *libbpfgo.PerfBuffer
	cgroupManager     *containers.Containers
	enrichEnabled     bool
}

func NewController(
	bpfModule *libbpfgo.Module,
	cgroupManager *containers.Containers,
	enrichEnabled bool,
) (*Controller, error) {
	var err error

	p := &Controller{
		signalChan:     make(chan []byte, 100),
		lostSignalChan: make(chan uint64),
		bpfModule:      bpfModule,
		cgroupManager:  cgroupManager,
		enrichEnabled:  enrichEnabled,
	}

	p.signalBuffer, err = bpfModule.InitPerfBuf("signals", p.signalChan, p.lostSignalChan, 1024)
	if err != nil {
		return nil, err
	}

	p.controlProbeGroup = probes.NewProbeGroup(
		bpfModule, map[probes.Handle]probes.Probe{
			cgroupMkdirControlProbe: probes.NewTraceProbe(
				probes.RawTracepoint,
				"cgroup:cgroup_mkdir",
				"cgroup_mkdir_signal",
			),
			cgroupRmdirControlProbe: probes.NewTraceProbe(
				probes.RawTracepoint,
				"cgroup:cgroup_rmdir",
				"cgroup_rmdir_signal",
			),
		},
	)

	return p, nil
}

func (p *Controller) Attach() error {
	controlProbes := []probes.Handle{
		cgroupMkdirControlProbe,
		cgroupRmdirControlProbe,
	}

	// Attach the control probes
	for _, probeHandle := range controlProbes {
		err := p.controlProbeGroup.Attach(probeHandle)
		if err != nil {
			return fmt.Errorf(
				"failed to attach control probe (program: %v): %v",
				p.controlProbeGroup.GetProgramNameByHandle(probeHandle),
				err,
			)
		}
	}

	return nil
}

func (p *Controller) Start() error {
	p.signalBuffer.Poll(pollTimeout)
	return nil
}

func (p *Controller) Run(ctx context.Context) {
	p.ctx = ctx
	for {
		select {
		case signalData := <-p.signalChan:
			signal := signal{}
			err := signal.Unmarshal(signalData)
			if err != nil {
				logger.Errorw("error unmarshaling signal ebpf buffer", "error", err)
				continue
			}
			err = p.processSignal(signal)
			if err != nil {
				logger.Errorw("error processing control plane signal", "error", err)
			}
		case lost := <-p.lostSignalChan:
			logger.Warnw(fmt.Sprintf("Lost %d control plane signals", lost))
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Controller) Stop() error {
	p.signalBuffer.Stop()
	return p.controlProbeGroup.DetachAll()
}

func (p *Controller) processSignal(signal signal) error {
	switch signal.eventID {
	case events.CgroupMkdir:
		return p.processCgroupMkdir(signal.args)
	case events.CgroupRmdir:
		return p.processCgroupRmdir(signal.args)
	case events.SchedProcessFork:
		return p.processSchedProcessFork(signal.args)
	case events.SchedProcessExec:
		return p.processSchedProcessExec(signal.args)
	case events.SchedProcessExit:
		return p.processSchedProcessExit(signal.args)
	}
	return nil
}

//
// TODO:
//
// If we agree that all signal events are just regular events without the event_context_t prefixing
// them, like the existing cases below, then we should create specific parsing functions for the
// arguments (instead of having a single parsing function to each signal type (just like we do in
// the regular pipeline). OR at least we should have a generic parsing function WHEN that is true
// (and allow other parsing functions in the case the signal event use other arguments than a
// regular existing event arguments.
//

func (p *Controller) processCgroupMkdir(args []trace.Argument) error {
	cgroupId, err := parse.ArgVal[uint64](args, "cgroup_id")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_mkdir signal args: %v", err)
	}
	path, err := parse.ArgVal[string](args, "cgroup_path")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_mkdir signal args: %v", err)
	}
	hId, err := parse.ArgVal[uint32](args, "hierarchy_id")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_mkdir signal args: %v", err)
	}
	info, err := p.cgroupManager.CgroupMkdir(cgroupId, path, hId)
	if err != nil {
		return errfmt.WrapError(err)
	}

	if info.Container.ContainerId == "" && !info.Dead {
		// If cgroupId is from a regular cgroup directory, and not the container base directory
		// (from known runtimes), it should be removed from the containers bpf map.
		err := capabilities.GetInstance().EBPF(
			func() error {
				return p.cgroupManager.RemoveFromBPFMap(p.bpfModule, cgroupId, hId)
			},
		)
		if err != nil {
			// If the cgroupId was not found in bpf map, this could mean that it is not a container
			// cgroup and, as a systemd cgroup, could have been created and removed very quickly.
			// In this case, we don't want to return an error.
			logger.Debugw("failed to remove entry from containers bpf map", "error", err)
		}
		return errfmt.WrapError(err)
	}

	if p.enrichEnabled {
		// If cgroupId belongs to a container, enrich now (in a goroutine)
		go func() {
			_, err := p.cgroupManager.EnrichCgroupInfo(cgroupId)
			if err != nil {
				logger.Errorw("error triggering container enrich in control plane", "error", err)
			}
		}()
	}

	return nil
}

func (p *Controller) processCgroupRmdir(args []trace.Argument) error {
	cgroupId, err := parse.ArgVal[uint64](args, "cgroup_id")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_rmdir signal args: %v", err)
	}
	hId, err := parse.ArgVal[uint32](args, "hierarchy_id")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_rmdir signal args: %v", err)
	}
	p.cgroupManager.CgroupRemove(cgroupId, hId)

	return nil
}

func (p *Controller) processSchedProcessFork(args []trace.Argument) error {
	var err error
	var file *os.File

	var parentTid, parentNsTid, parentPid, parentNsPid int32
	var childTid, childNsTid, childPid, childNsPid int32
	var parentStartTime, startTime uint64

	if len(args) != 10 {
		err = errfmt.Errorf("got %d args instead of %d", len(args), 10)
		goto failed
	}

	// Parent
	parentTid, err = parse.ArgVal[int32](args, "parent_tid")
	if err != nil {
		goto failed
	}
	parentNsTid, err = parse.ArgVal[int32](args, "parent_ns_tid")
	if err != nil {
		goto failed
	}
	parentPid, err = parse.ArgVal[int32](args, "parent_pid")
	if err != nil {
		goto failed
	}
	parentNsPid, err = parse.ArgVal[int32](args, "parent_ns_pid")
	if err != nil {
		goto failed
	}
	// Child
	childTid, err = parse.ArgVal[int32](args, "child_tid")
	if err != nil {
		goto failed
	}
	childNsTid, err = parse.ArgVal[int32](args, "child_ns_tid")
	if err != nil {
		goto failed
	}
	childPid, err = parse.ArgVal[int32](args, "child_pid")
	if err != nil {
		goto failed
	}
	childNsPid, err = parse.ArgVal[int32](args, "child_ns_pid")
	if err != nil {
		goto failed
	}
	// Times
	parentStartTime, err = parse.ArgVal[uint64](args, "parent_start_time")
	if err != nil {
		goto failed
	}
	startTime, err = parse.ArgVal[uint64](args, "start_time")
	if err != nil {
		goto failed
	}

	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	// file = os.Stdout
	fmt.Fprintf(file, "--\nFork event received:\n")
	fmt.Fprintf(file, "Parent: tid=%d ns_tid=%d pid=%d ns_pid=%d\n", parentTid, parentNsTid, parentPid, parentNsPid)
	fmt.Fprintf(file, "Child: tid=%d ns_tid=%d pid=%d ns_pid=%d\n", childTid, childNsTid, childPid, childNsPid)
	fmt.Fprintf(file, "parentStartTime=%d\n", parentStartTime)
	fmt.Fprintf(file, "startTime=%d\n", startTime)
	fmt.Fprintf(file, "--\n")
	// END OF DEBUG

	return nil

failed:
	return errfmt.Errorf("error parsing SchedProcessFork signal args: %v", err)
}

func (p *Controller) processSchedProcessExec(args []trace.Argument) error {
	var err error
	var file *os.File

	var cmdPath, pathName, interPathName, interpreter, stdinPath string
	var dev, interDev uint32
	var inode, ctime, interInode, interCtime uint64
	var inodeMode, stdinType uint16
	var invokedFromKernel int32

	if len(args) != 16 {
		err = errfmt.Errorf("got %d args instead of %d", len(args), 16)
		goto failed
	}

	// string
	cmdPath, err = parse.ArgVal[string](args, "cmdpath")
	if err != nil {
		goto failed
	}
	pathName, err = parse.ArgVal[string](args, "pathname")
	if err != nil {
		goto failed
	}
	interPathName, err = parse.ArgVal[string](args, "interpreter_pathname")
	if err != nil {
		goto failed
	}
	interpreter, err = parse.ArgVal[string](args, "interp")
	if err != nil {
		goto failed
	}
	stdinPath, err = parse.ArgVal[string](args, "stdin_path")
	if err != nil {
		goto failed
	}
	// dev_t(uint32)
	dev, err = parse.ArgVal[uint32](args, "dev")
	if err != nil {
		goto failed
	}
	interDev, err = parse.ArgVal[uint32](args, "interpreter_dev")
	if err != nil {
		goto failed
	}
	// uint64
	inode, err = parse.ArgVal[uint64](args, "inode")
	if err != nil {
		goto failed
	}
	ctime, err = parse.ArgVal[uint64](args, "ctime")
	if err != nil {
		goto failed
	}
	interInode, err = parse.ArgVal[uint64](args, "interpreter_inode")
	if err != nil {
		goto failed
	}
	interCtime, err = parse.ArgVal[uint64](args, "interpreter_ctime")
	if err != nil {
		goto failed
	}
	// uint16
	inodeMode, err = parse.ArgVal[uint16](args, "inode_mode")
	if err != nil {
		goto failed
	}
	stdinType, err = parse.ArgVal[uint16](args, "stdin_type")
	if err != nil {
		goto failed
	}
	// int32
	invokedFromKernel, err = parse.ArgVal[int32](args, "invoked_from_kernel")
	if err != nil {
		goto failed
	}

	// TODO: deal with argv and envp if ever needed

	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	// file = os.Stdout
	fmt.Fprintf(file, "--\nExec event received:\n")
	fmt.Fprintf(file, "cmdPath=%s\n", cmdPath)
	fmt.Fprintf(file, "pathName=%s\n", pathName)
	fmt.Fprintf(file, "interPathName=%s\n", interPathName)
	fmt.Fprintf(file, "interpreter=%s\n", interpreter)
	fmt.Fprintf(file, "stdinPath=%s\n", stdinPath)
	fmt.Fprintf(file, "dev=%d\n", dev)
	fmt.Fprintf(file, "interDev=%d\n", interDev)
	fmt.Fprintf(file, "inode=%d\n", inode)
	fmt.Fprintf(file, "ctime=%d\n", ctime)
	fmt.Fprintf(file, "interInode=%d\n", interInode)
	fmt.Fprintf(file, "interCtime=%d\n", interCtime)
	fmt.Fprintf(file, "inodeMode=%d\n", inodeMode)
	fmt.Fprintf(file, "stdinType=%d\n", stdinType)
	fmt.Fprintf(file, "invokedFromKernel=%d\n", invokedFromKernel)
	fmt.Fprintf(file, "--\n")
	// END OF DEBUG

	return nil

failed:
	return errfmt.Errorf("error parsing SchedProcessExec signal args: %v", err)
}

func (p *Controller) processSchedProcessExit(args []trace.Argument) error {
	var err error
	var file *os.File

	var exitCode int64
	var exitTime uint64
	var hostPid int32
	var groupExit bool

	if len(args) != 4 {
		err = errfmt.Errorf("got %d args instead of %d", len(args), 4)
		goto failed
	}

	// int64
	exitCode, err = parse.ArgVal[int64](args, "exit_code")
	if err != nil {
		goto failed
	}
	// uint64
	exitTime, err = parse.ArgVal[uint64](args, "exit_time")
	if err != nil {
		goto failed
	}
	// int32
	hostPid, err = parse.ArgVal[int32](args, "host_pid")
	if err != nil {
		goto failed
	}
	// bool
	groupExit, err = parse.ArgVal[bool](args, "process_group_exit")
	if err != nil {
		goto failed
	}

	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	// file = os.Stdout
	fmt.Fprintf(file, "--\nExit event received:\n")
	fmt.Fprintf(file, "exitCode=%d\n", exitCode)
	fmt.Fprintf(file, "groupExit=%t\n", groupExit)
	fmt.Fprintf(file, "exitTime=%d\n", exitTime)
	fmt.Fprintf(file, "hostPid=%d\n", hostPid)
	fmt.Fprintf(file, "--\n")
	// END OF DEBUG

	return nil

failed:
	return errfmt.Errorf("error parsing SchedProcessExit signal args: %v", err)
}
