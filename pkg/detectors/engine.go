package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// Engine is the main detector engine that orchestrates registration and dispatch
type Engine struct {
	registry          *registry
	dispatcher        *dispatcher
	metrics           *Metrics
	enrichmentOptions *EnrichmentOptions
}

// NewEngine creates a new detector engine
func NewEngine(policyManager *policy.Manager, enrichmentOptions *EnrichmentOptions) *Engine {
	registry := newRegistry(policyManager, enrichmentOptions)
	metrics := NewMetrics()
	return &Engine{
		registry:          registry,
		dispatcher:        newDispatcher(registry, policyManager, metrics),
		metrics:           metrics,
		enrichmentOptions: enrichmentOptions,
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
	e.dispatcher.rebuild()

	return nil
}

// GetDetectorCount returns the number of registered detectors
func (e *Engine) GetDetectorCount() int {
	return e.registry.GetDetectorCount()
}

// UnregisterDetector unregisters a detector from the engine
func (e *Engine) UnregisterDetector(detectorID string) error {
	// Unregister from registry
	if err := e.registry.UnregisterDetector(detectorID); err != nil {
		return err
	}

	// Rebuild dispatch map after unregistration
	e.dispatcher.rebuild()

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
	return e.dispatcher.dispatchToDetectors(ctx, inputEvent)
}

// GetMetrics returns the detector metrics instance
func (e *Engine) GetMetrics() *Metrics {
	return e.metrics
}

// RegisterPrometheusMetrics registers detector metrics with Prometheus
func (e *Engine) RegisterPrometheusMetrics() error {
	return e.metrics.RegisterPrometheus()
}
