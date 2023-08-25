package controlplane

import (
	"context"
	"fmt"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
)

// TODO: With the introduction of signal events, the control plane can now have a generic argument
// parsing, just like the regular pipeline. So all arguments can be parsed before the handlers are
// called.

const pollTimeout int = 300 // from tracee.go (move to a consts package?)

type Controller struct {
	ctx            context.Context
	signalChan     chan []byte
	lostSignalChan chan uint64
	bpfModule      *libbpfgo.Module
	signalBuffer   *libbpfgo.PerfBuffer
	cgroupManager  *containers.Containers
	processTree    *proctree.ProcessTree
	enrichEnabled  bool
}

func NewController(
	bpfModule *libbpfgo.Module,
	cgroupManager *containers.Containers,
	enrichEnabled bool,
	procTree *proctree.ProcessTree,
) (*Controller, error) {
	var err error

	p := &Controller{
		signalChan:     make(chan []byte, 100),
		lostSignalChan: make(chan uint64),
		bpfModule:      bpfModule,
		cgroupManager:  cgroupManager,
		processTree:    procTree,
		enrichEnabled:  enrichEnabled,
	}

	p.signalBuffer, err = bpfModule.InitPerfBuf("signals", p.signalChan, p.lostSignalChan, 1024)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (ctrl *Controller) Start() {
	ctrl.signalBuffer.Poll(pollTimeout)
}

func (ctrl *Controller) Run(ctx context.Context) {
	ctrl.ctx = ctx
	for {
		select {
		case signalData := <-ctrl.signalChan:
			signal := signal{}
			err := signal.Unmarshal(signalData)
			if err != nil {
				logger.Errorw("error unmarshaling signal ebpf buffer", "error", err)
				continue
			}
			err = ctrl.processSignal(signal)
			if err != nil {
				logger.Errorw("error processing control plane signal", "error", err)
			}
		case lost := <-ctrl.lostSignalChan:
			logger.Warnw(fmt.Sprintf("Lost %d control plane signals", lost))
		case <-ctrl.ctx.Done():
			return
		}
	}
}

func (ctrl *Controller) Stop() error {
	ctrl.signalBuffer.Stop()
	return nil
}

func (ctrl *Controller) processSignal(signal signal) error {
	switch signal.eventID {
	case events.SignalCgroupMkdir:
		return ctrl.processCgroupMkdir(signal.args)
	case events.SignalCgroupRmdir:
		return ctrl.processCgroupRmdir(signal.args)
	case events.SignalSchedProcessFork:
		return ctrl.processSchedProcessFork(signal.args)
	case events.SignalSchedProcessExec:
		return ctrl.processSchedProcessExec(signal.args)
	case events.SignalSchedProcessExit:
		return ctrl.processSchedProcessExit(signal.args)
	}
	return nil
}
