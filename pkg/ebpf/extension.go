package ebpf

import (
	"context"
	"reflect"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// Extension interface for Tracee
type Extension interface {
	// Initialize the extension
	Init(t *Tracee) error
	// Register initialization events which are emitted by the extension
	RegisterInitEvents(t *Tracee, out chan *trace.Event) error
	// Run the extension
	Run(ctx context.Context, t *Tracee) error
	// Close the extension
	Close() error
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

func GetRegisteredExtensions() []Extension {
	return extensionRegistry
}
