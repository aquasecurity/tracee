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
func (e *DummyExtension) Init(t *ebpf.Tracee) error {
	logger.Debugw("DummyExtension Init")
	e.initialized = true
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
		fmt.Println("DummyExtension not initialized")
		return nil
	}
	return nil
}

// Close closes the DummyExtension
func (e *DummyExtension) Close() error {
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
