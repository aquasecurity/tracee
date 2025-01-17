package controlplane

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	signalPool     *sync.Pool
	cgroupManager  *containers.Containers
	processTree    *proctree.ProcessTree
	enrichDisabled bool
}

// NewController creates a new controller.
func NewController(
	bpfModule *libbpfgo.Module,
	cgroupManager *containers.Containers,
	enrichDisabled bool,
	procTree *proctree.ProcessTree,
) (*Controller, error) {
	var err error

	p := &Controller{
		signalChan:     make(chan []byte, 100),
		lostSignalChan: make(chan uint64),
		bpfModule:      bpfModule,
		signalPool: &sync.Pool{
			New: func() interface{} {
				return &signal{}
			},
		},
		cgroupManager:  cgroupManager,
		processTree:    procTree,
		enrichDisabled: enrichDisabled,
	}

	p.signalBuffer, err = bpfModule.InitPerfBuf("signals", p.signalChan, p.lostSignalChan, 1024)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Start starts the controller.
func (ctrl *Controller) Start() {
	ctrl.signalBuffer.Poll(pollTimeout)
}

// Run runs the controller.
func (ctrl *Controller) Run(ctx context.Context) {
	ctrl.ctx = ctx
	ctrl.debug(false) // change this to "true" to enable process tree printing periodically.

	for {
		select {
		case signalData := <-ctrl.signalChan:
			signal := ctrl.getSignalFromPool()

			// NOTE: override all the fields of the signal, to avoid any previous data.
			err := signal.Unmarshal(signalData)
			if err != nil {
				logger.Errorw("error unmarshaling signal ebpf buffer", "error", err)
				ctrl.putSignalInPool(signal)
				continue
			}

			err = ctrl.processSignal(signal)
			if err != nil {
				logger.Errorw("error processing control plane signal", "error", err)
			}

			ctrl.putSignalInPool(signal)
		case lost := <-ctrl.lostSignalChan:
			logger.Warnw(fmt.Sprintf("Lost %d control plane signals", lost))
		case <-ctrl.ctx.Done():
			return
		}
	}
}

// Stop stops the controller.
func (ctrl *Controller) Stop() error {
	ctrl.signalBuffer.Stop()
	return nil
}

// Private

// processSignal processes a signal from the control plane.
func (ctrl *Controller) processSignal(signal *signal) error {
	switch signal.id {
	case events.SignalCgroupMkdir:
		return ctrl.processCgroupMkdir(signal.args)
	case events.SignalCgroupRmdir:
		return ctrl.processCgroupRmdir(signal.args)
	case events.SignalSchedProcessFork:
		return ctrl.procTreeForkProcessor(signal.args)
	case events.SignalSchedProcessExec:
		return ctrl.procTreeExecProcessor(signal.args)
	case events.SignalSchedProcessExit:
		return ctrl.procTreeExitProcessor(signal.args)
	}

	return nil
}

// getSignalFromPool gets a signal from the pool.
// signal certainly contains old data, so it must be updated before use.
func (ctrl *Controller) getSignalFromPool() *signal {
	// revive:disable:unchecked-type-assertion
	sig := ctrl.signalPool.Get().(*signal)
	// revive:enable:unchecked-type-assertion

	return sig
}

// putSignalInPool puts a signal back in the pool.
func (ctrl *Controller) putSignalInPool(sig *signal) {
	ctrl.signalPool.Put(sig)
}

// debug prints the process tree every 5 seconds (for debugging purposes).
func (ctrl *Controller) debug(enable bool) {
	//
	// The "best way" to debug hash problems is:
	//
	// 1. To enable the process tree "display" (this function);
	// 2. To bpf_printk the "hash" and "start_time" at sched_process_exit_signal() in eBPF code;
	// 3. To start a simple multi-threaded application (with processes and threads): https://gist.github.com/rafaeldtinoco/4b0a13213283ad636d5cc33be053a817
	// 4. To start tracee.
	//
	// Wait for the tree to be printed by proctree_output.go code (with "main" program on it, and
	// its threads), exit "main program" and check "bpf tracelog". You will be able to compare the
	// hash from the exit hook with the process tree one (and check different values).
	//
	// You may also execute "main" program after tracee has started, with debug enabled, and check
	// if the process tree shows it, and its threads, correctly.
	//
	// NOTE: Of course there are other ways of debugging, this one is the fastest and simpler
	// (without adding/removing too much code).

	if enable && ctrl.processTree != nil { // debug AND process tree are enabled
		go func() {
			for {
				time.Sleep(5 * time.Second)
				fmt.Printf("%s", ctrl.processTree)
			}
		}()
	}
}
