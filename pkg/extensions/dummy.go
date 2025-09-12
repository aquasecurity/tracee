package extensions

import (
	"context"
	"fmt"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/types/trace"
)

// DummyExtension is a dummy extension for testing
type DummyExtension struct {
	name        string
	initialized bool
}

// NewDummyExtension creates a new DummyExtension
func NewDummyExtension() ebpf.Extension {
	return &DummyExtension{
		name:        "Dummy Extension",
		initialized: false,
	}
}

// Init initializes the DummyExtension
func (e *DummyExtension) Init(ctx context.Context, t *ebpf.Tracee, phase ebpf.InitPhase) error {
	switch phase {
	case ebpf.INIT_START:
		logger.Debugw("DummyExtension Init", "phase", "INIT_START")
		e.initialized = true
	case ebpf.INIT_CGROUPS:
		logger.Debugw("DummyExtension Init", "phase", "INIT_CGROUPS")
	case ebpf.INIT_CONTAINERS:
		logger.Debugw("DummyExtension Init", "phase", "INIT_CONTAINERS")
	case ebpf.INIT_BPF_PROBES:
		logger.Debugw("DummyExtension Init", "phase", "INIT_BPF_PROBES")
	case ebpf.INIT_KERNEL_SYMBOLS:
		logger.Debugw("DummyExtension Init", "phase", "INIT_KERNEL_SYMBOLS")
	case ebpf.INIT_BPF_PROGRAMS:
		logger.Debugw("DummyExtension Init", "phase", "INIT_BPF_PROGRAMS")
	case ebpf.INIT_COMPLETE:
		logger.Debugw("DummyExtension Init", "phase", "INIT_COMPLETE")
	default:
		return fmt.Errorf("unknown initialization phase: %d", phase)
	}
	return nil
}

// RegisterInitEvents registers the initialization events for the DummyExtension
func (e *DummyExtension) RegisterInitEvents(t *ebpf.Tracee, out chan *trace.Event) error {
	logger.Debugw("DummyExtension RegisterInitEvents")
	if !e.initialized {
		logger.Debugw("DummyExtension not initialized")
		return nil
	}
	return nil
}

// Run runs the DummyExtension
func (e *DummyExtension) Run(ctx context.Context, t *ebpf.Tracee) error {
	logger.Debugw("DummyExtension Run")
	if !e.initialized {
		logger.Debugw("DummyExtension not initialized")
		return nil
	}
	return nil
}

// Close closes the DummyExtension
func (e *DummyExtension) Close(t *ebpf.Tracee) error {
	logger.Debugw("DummyExtension Close")
	if !e.initialized {
		logger.Debugw("DummyExtension not initialized")
		return nil
	}
	return nil
}

func init() {
	ebpf.RegisterExtension(NewDummyExtension())
}
