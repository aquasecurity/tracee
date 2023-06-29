package controlplane

import (
	"context"
	"fmt"

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

type Controller struct {
	ctx            context.Context
	signalChan     chan []byte
	lostSignalChan chan uint64
	bpfModule      *libbpfgo.Module
	probeGroup     *probes.ProbeGroup
	signalBuffer   *libbpfgo.PerfBuffer
	cgroupManager  *containers.Containers
	enrichEnabled  bool
}

func NewController(bpfModule *libbpfgo.Module, cgroupManager *containers.Containers, enrichEnabled bool) (*Controller, error) {
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

	p.probeGroup = probes.NewProbeGroup(bpfModule, map[probes.Handle]probes.Probe{
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
	})

	return p, nil
}

func (p *Controller) Attach() error {
	err := p.probeGroup.Attach(cgroupMkdirControlProbe)
	if err != nil {
		return fmt.Errorf("failed to attach cgroup_mkdir probe in control plane: %v", err)
	}
	err = p.probeGroup.Attach(cgroupRmdirControlProbe)
	if err != nil {
		return fmt.Errorf("failed to attach cgroup_rmdir probe in control plane: %v", err)
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
	return p.probeGroup.DetachAll()
}

func (p *Controller) processSignal(signal signal) error {
	switch signal.eventID {
	case events.CgroupMkdir:
		return p.processCgroupMkdir(signal.args)
	case events.CgroupRmdir:
		return p.processCgroupRmdir(signal.args)
	}
	return nil
}

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
	if info.Container.ContainerId == "" {
		// If cgroupId is from a regular cgroup directory, and not the
		// container base directory (from known runtimes), it should be
		// removed from the containers bpf map.
		err := capabilities.GetInstance().EBPF(
			func() error {
				return p.cgroupManager.RemoveFromBPFMap(p.bpfModule, cgroupId, hId)
			},
		)
		if err != nil {
			// If the cgroupId was not found in bpf map, this could mean that
			// it is not a container cgroup and, as a systemd cgroup, could have been
			// created and removed very quickly.
			// In this case, we don't want to return an error.
			logger.Debugw("Failed to remove entry from containers bpf map", "error", err)
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
		return errfmt.Errorf("error parsing cgroup_rmdir args: %v", err)
	}

	hId, err := parse.ArgVal[uint32](args, "hierarchy_id")
	if err != nil {
		return errfmt.Errorf("error parsing cgroup_rmdir args: %v", err)
	}
	p.cgroupManager.CgroupRemove(cgroupId, hId)
	return nil
}
