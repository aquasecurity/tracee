package controlplane

import (
	"context"
	"fmt"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
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
	enrichEnabled  bool
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

	return p, nil
}

func (p *Controller) Start() {
	p.signalBuffer.Poll(pollTimeout)
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
	return nil
}

func (p *Controller) processSignal(signal signal) error {
	switch signal.eventID {
	case events.SignalCgroupMkdir:
		return p.processCgroupMkdir(signal.args)
	case events.SignalCgroupRmdir:
		return p.processCgroupRmdir(signal.args)
	case events.SignalSchedProcessFork:
		return p.processSchedProcessFork(signal.args)
	case events.SignalSchedProcessExec:
		return p.processSchedProcessExec(signal.args)
	case events.SignalSchedProcessExit:
		return p.processSchedProcessExit(signal.args)
	}
	return nil
}
