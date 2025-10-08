package controlplane

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/ebpf/heartbeat"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/types/trace"
)

// TODO: With the introduction of signal events, the control plane can now have a generic argument
// parsing, just like the regular pipeline. So all arguments can be parsed before the handlers are
// called.

const pollTimeout int = 300 // from tracee.go (move to a consts package?)

// SignalHandler defines a function that can process control plane signals
type SignalHandler func(signalID events.ID, args []trace.Argument) error

type Controller struct {
	ctx            context.Context
	signalChan     chan []byte
	lostSignalChan chan uint64
	bpfModule      *libbpfgo.Module
	signalBuffer   *libbpfgo.PerfBuffer
	signalPool     *sync.Pool
	cgroupManager  *containers.Manager
	processTree    *proctree.ProcessTree
	enrichDisabled bool
	dataPresentor  bufferdecoder.TypeDecoder
	signalHandlers map[events.ID]SignalHandler
}

// NewController creates a new controller.
func NewController(
	bpfModule *libbpfgo.Module,
	cgroupManager *containers.Manager,
	enrichDisabled bool,
	procTree *proctree.ProcessTree,
	dataPresentor bufferdecoder.TypeDecoder,
) *Controller {
	return &Controller{
		signalChan:     make(chan []byte, 100),
		lostSignalChan: make(chan uint64),
		bpfModule:      bpfModule,
		signalPool: &sync.Pool{
			New: func() interface{} {
				return &Signal{}
			},
		},
		cgroupManager:  cgroupManager,
		processTree:    procTree,
		enrichDisabled: enrichDisabled,
		dataPresentor:  dataPresentor,
		signalHandlers: make(map[events.ID]SignalHandler),
	}
}

func (ctrl *Controller) Init() error {
	var err error
	ctrl.signalBuffer, err = ctrl.bpfModule.InitPerfBuf("signals", ctrl.signalChan, ctrl.lostSignalChan, 1024)
	if err != nil {
		return err
	}

	err = ctrl.registerBuiltinSignals()
	if err != nil {
		return errfmt.Errorf("failed to register signal handlers: %v", err)
	}

	return nil
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
			err := signal.Unmarshal(signalData, ctrl.dataPresentor)
			if err != nil {
				logger.Errorw("error unmarshaling signal ebpf buffer", "error", err)
				ctrl.putSignalInPool(signal)
				continue
			}

			err = ctrl.ProcessSignal(signal)
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

// RegisterSignal registers multiple signal handlers at once
func (ctrl *Controller) RegisterSignal(handlers map[events.ID]SignalHandler) error {
	// Validate all handlers before making any changes (atomic operation)
	for signalID, handler := range handlers {
		if handler == nil {
			return errfmt.Errorf("signal handler for signal ID %d cannot be nil", signalID)
		}
		if _, exists := ctrl.signalHandlers[signalID]; exists {
			return errfmt.Errorf("signal handler for signal ID %d already exists", signalID)
		}
	}

	// All validations passed, now register each handler
	for signalID, handler := range handlers {
		ctrl.signalHandlers[signalID] = handler
	}

	return nil
}

// ProcessSignal processes a signal from the control plane.
func (ctrl *Controller) ProcessSignal(signal *Signal) error {
	handler, exists := ctrl.signalHandlers[signal.ID]
	if !exists {
		return errfmt.Errorf("no registered handler for signal %d", signal.ID)
	}

	return handler(signal.ID, signal.Data)
}

func (ctrl *Controller) HasSignalHandler(signalID events.ID) bool {
	_, exists := ctrl.signalHandlers[signalID]
	return exists
}

// Private

// registerBuiltinSignals registers all default signal handlers
func (ctrl *Controller) registerBuiltinSignals() error {
	// Define all signal handlers in a map for batch registration
	signalHandlers := map[events.ID]SignalHandler{
		events.SignalCgroupMkdir: func(signalID events.ID, args []trace.Argument) error {
			return ctrl.processCgroupMkdir(args)
		},
		events.SignalCgroupRmdir: func(signalID events.ID, args []trace.Argument) error {
			return ctrl.processCgroupRmdir(args)
		},
		events.SignalSchedProcessFork: func(signalID events.ID, args []trace.Argument) error {
			// Not normalized at decode - normalize here.
			err := events.NormalizeTimeArgs(
				args,
				[]string{
					"timestamp",
					"parent_process_start_time",
					"leader_start_time",
					"start_time",
				},
			)
			if err != nil {
				signalName := events.Core.GetDefinitionByID(signalID).GetName()
				return errfmt.Errorf("error normalizing time args for signal %s: %v", signalName, err)
			}

			return ctrl.procTreeForkProcessor(args)
		},
		events.SignalSchedProcessExec: func(signalID events.ID, args []trace.Argument) error {
			// Not normalized at decode - normalize here.
			err := events.NormalizeTimeArgs(
				args,
				[]string{
					"timestamp",
					"task_start_time",
					"parent_start_time",
					"leader_start_time",
				},
			)
			if err != nil {
				signalName := events.Core.GetDefinitionByID(signalID).GetName()
				return errfmt.Errorf("error normalizing time args for signal %s: %v", signalName, err)
			}

			return ctrl.procTreeExecProcessor(args)
		},
		events.SignalSchedProcessExit: func(signalID events.ID, args []trace.Argument) error {
			// Not normalized at decode - normalize here.
			err := events.NormalizeTimeArgs(
				args,
				[]string{
					"timestamp",
					"task_start_time",
				},
			)
			if err != nil {
				signalName := events.Core.GetDefinitionByID(signalID).GetName()
				return errfmt.Errorf("error normalizing time args for signal %s: %v", signalName, err)
			}

			return ctrl.procTreeExitProcessor(args)
		},
		events.SignalHeartbeat: func(signalID events.ID, args []trace.Argument) error {
			heartbeat.SendPulse()
			return nil
		},
	}

	// Register all handlers
	return ctrl.RegisterSignal(signalHandlers)
}

// getSignalFromPool gets a signal from the pool.
// signal certainly contains old data, so it must be updated before use.
func (ctrl *Controller) getSignalFromPool() *Signal {
	// revive:disable:unchecked-type-assertion
	sig := ctrl.signalPool.Get().(*Signal)
	// revive:enable:unchecked-type-assertion

	return sig
}

// putSignalInPool puts a signal back in the pool.
func (ctrl *Controller) putSignalInPool(sig *Signal) {
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
