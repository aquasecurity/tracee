package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// Engine is the main detector engine that orchestrates registration and dispatch
type Engine struct {
	registry   *registry
	dispatcher *dispatcher
}

// NewEngine creates a new detector engine
func NewEngine() *Engine {
	return &Engine{
		registry:   newRegistry(),
		dispatcher: newDispatcher(),
	}
}

// RegisterDetector registers a detector with the engine
func (e *Engine) RegisterDetector(
	detector detection.EventDetector,
	params detection.DetectorParams,
) error {
	// Register with registry
	if err := e.registry.RegisterDetector(detector, params); err != nil {
		return err
	}

	// Rebuild dispatch map after registration
	e.dispatcher.rebuild(e.registry)

	return nil
}

// UnregisterDetector unregisters a detector from the engine
func (e *Engine) UnregisterDetector(detectorID string) error {
	// Unregister from registry
	if err := e.registry.UnregisterDetector(detectorID); err != nil {
		return err
	}

	// Rebuild dispatch map after unregistration
	e.dispatcher.rebuild(e.registry)

	return nil
}

// ListDetectors returns all registered detector IDs
func (e *Engine) ListDetectors() []string {
	return e.registry.ListDetectors()
}

// GetDetector retrieves a detector by ID
func (e *Engine) GetDetector(detectorID string) (detection.EventDetector, error) {
	return e.registry.GetDetector(detectorID)
}

// EnableDetector enables a registered detector
func (e *Engine) EnableDetector(detectorID string) error {
	return e.registry.EnableDetector(detectorID)
}

// DisableDetector disables a registered detector
func (e *Engine) DisableDetector(detectorID string) error {
	return e.registry.DisableDetector(detectorID)
}

// DispatchToDetectors dispatches an event to all registered detectors that are interested in it
// Returns the output events produced by detectors
func (e *Engine) DispatchToDetectors(ctx context.Context, inputEvent *v1beta1.Event) ([]*v1beta1.Event, error) {
	return e.dispatcher.dispatchToDetectors(ctx, inputEvent, e.registry)
}
