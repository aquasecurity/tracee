package ebpf

import (
	"context"
	"reflect"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// InitPhase represents different phases of extension initialization
// Extensions should implement a switch case in their Init method to handle different phases
type InitPhase int

const (
	// Early initialization phases
	INIT_START          InitPhase = iota // At the start of initialization
	INIT_CGROUPS                         // After cgroups filesystems initialization
	INIT_CONTAINERS                      // After containers initialization
	INIT_BPF_PROBES                      // After eBPF probes initialization
	INIT_KERNEL_SYMBOLS                  // After kernel symbols initialization
	INIT_BPF_PROGRAMS                    // After eBPF programs and maps initialization
	INIT_COMPLETE                        // At the end of initialization, before returning
)

// Extension interface for Tracee
type Extension interface {
	// Initialize the extension with a specific phase
	Init(ctx context.Context, t *Tracee, phase InitPhase) error
	// Register initialization events which are emitted by the extension
	RegisterInitEvents(t *Tracee, out chan *trace.Event) error
	// Run the extension
	Run(ctx context.Context, t *Tracee) error
	// Close the extension
	Close(t *Tracee) error
}

type ExtensionCallbacks struct {
	// Event attach callbacks
	EventAttachCallbacks []EventCallback

	// Probe handlers for extensible probe processing
	probeHandlers map[reflect.Type]func(definition events.Definition, probe interface{}) (bool, string)
}

type EventCallback func(event interface{})

func (t *Tracee) RegisterExternalEvent(callback EventCallback) {
	t.extensionCallbacks.EventAttachCallbacks = append(t.extensionCallbacks.EventAttachCallbacks, callback)
}

// processExternalProbe processes probes using registered external handlers
func (t *Tracee) processExternalEvent(probe events.Probe) {
	for _, eventCallback := range t.extensionCallbacks.EventAttachCallbacks {
		eventCallback(probe)
	}
}

// RegisterProbeHandler registers a probe handler for the given probe type
// The handler function should return (shouldCount, name) where:
// - shouldCount: whether this probe should be counted in selfLoadedPrograms
// - name: the name to use as key in selfLoadedPrograms map
func (t *Tracee) RegisterExternalProbe(probeType reflect.Type, handler func(definition events.Definition, probe interface{}) (bool, string)) {
	if t.extensionCallbacks.probeHandlers == nil {
		t.extensionCallbacks.probeHandlers = make(map[reflect.Type]func(events.Definition, interface{}) (bool, string))
	}
	t.extensionCallbacks.probeHandlers[probeType] = handler
}

// processExternalProbe processes probes using registered external handlers
func (t *Tracee) processExternalProbe(definition events.Definition, probe interface{}) (bool, string) {
	// Get the actual type of the probe
	probeType := reflect.TypeOf(probe)

	if t.extensionCallbacks.probeHandlers == nil {
		// No handlers registered
		return false, ""
	}

	handler, exists := t.extensionCallbacks.probeHandlers[probeType]
	if !exists {
		// No registered handler for this probe type
		return false, ""
	}

	return handler(definition, probe)
}

var extensionRegistry []Extension

func RegisterExtension(ext Extension) {
	extensionRegistry = append(extensionRegistry, ext)
}

// loadExtensions loads all registered extensions from the global registry.
func (t *Tracee) loadExtensions() {
	t.extensions = extensionRegistry
}

// initExtensionsWithPhase initializes all loaded extensions with the specified phase
func (t *Tracee) initExtensionsWithPhase(ctx context.Context, phase InitPhase) error {
	for _, ext := range t.extensions {
		if err := ext.Init(ctx, t, phase); err != nil {
			return errfmt.Errorf("error initializing extension with phase %d: %v", phase, err)
		}
	}
	return nil
}

// runExtensions runs all loaded extensions
func (t *Tracee) runExtensions(ctx context.Context) error {
	for _, ext := range t.extensions {
		if err := ext.Run(ctx, t); err != nil {
			return errfmt.Errorf("error running extension: %v", err)
		}
	}
	return nil
}

// closeExtensions close all loaded extensions
func (t *Tracee) closeExtensions() error {
	for _, ext := range t.extensions {
		if err := ext.Close(t); err != nil {
			return errfmt.Errorf("error running extension: %v", err)
		}
	}
	return nil
}
