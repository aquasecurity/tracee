package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/metrics"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

const ALL_EVENT_ORIGINS = "*"
const EVENT_CONTAINER_ORIGIN = "container"
const EVENT_HOST_ORIGIN = "host"
const ALL_EVENT_TYPES = "*"

type Mode uint8

const (
	ModeRules Mode = iota
	ModeAnalyze
	ModeSingleBinary
)

// Config defines the engine's configurable values
type Config struct {
	Mode                Mode               // Engine in pipeline mode, can be ModeRules, ModeAnalyze or ModeSingleBinary
	NoSignatures        bool               // Skip signature processing while keeping events loaded (for performance testing)
	AvailableSignatures []detect.Signature // All available signatures found in signature directories
	SelectedSignatures  []detect.Signature // Only signatures that should be loaded based on user policies/events
	DataSources         []detect.DataSource
}

// Engine is a signatures-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	signatures       map[detect.Signature]struct{}
	signaturesIndex  map[detect.SignatureEventSelector][]detect.Signature
	signaturesMutex  sync.RWMutex
	inputs           EventSources
	output           chan *detect.Finding
	config           Config
	stats            metrics.Stats
	dataSources      map[string]map[string]detect.DataSource
	dataSourcesMutex sync.RWMutex
}

// EventSources is a bundle of input sources used to configure the Engine
type EventSources struct {
	Tracee chan protocol.Event
}

func (engine *Engine) Stats() *metrics.Stats {
	return &engine.stats
}

// NewEngine creates a new signatures-engine with the given arguments
// inputs and outputs are given as channels created by the consumer
// Signatures are not loaded at this point, Init must be called to perform config side effects.
func NewEngine(config Config, sources EventSources, output chan *detect.Finding) (*Engine, error) {
	if sources.Tracee == nil || output == nil {
		return nil, errors.New("nil input received")
	}
	engine := Engine{}

	engine.inputs = sources
	engine.output = output
	engine.config = config

	engine.signaturesMutex.Lock()
	engine.signatures = make(map[detect.Signature]struct{})
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
	engine.signaturesMutex.Unlock()

	engine.dataSourcesMutex.Lock()
	engine.dataSources = map[string]map[string]detect.DataSource{}
	engine.dataSourcesMutex.Unlock()

	return &engine, nil
}

// Init loads and initializes signatures and data sources passed in NewEngine.
// The split allows the loading of additional signatures and data sources between
// NewEngine and Start if needed.
func (engine *Engine) Init() error {
	for _, dataSource := range engine.config.DataSources {
		err := engine.RegisterDataSource(dataSource)
		if err != nil {
			logger.Errorw("Loading signatures data source: " + err.Error())
		}
	}

	// Load only selected signatures instead of all available signatures
	logger.Debugw("Loading signatures", "total_available", len(engine.config.AvailableSignatures), "selected_for_loading", len(engine.config.SelectedSignatures))
	for _, sig := range engine.config.SelectedSignatures {
		_, err := engine.loadSignature(sig)
		if err != nil {
			logger.Errorw("Loading signature: " + err.Error())
		}
	}

	return nil
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(ctx context.Context) {
	defer engine.unloadAllSignatures()
	logger.Debugw("Starting signature engine")
	engine.consumeSources(ctx)
}

func (engine *Engine) unloadAllSignatures() {
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	for sig := range engine.signatures {
		sig.Close()
		delete(engine.signatures, sig)
	}
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
}

// matchHandler is a function that runs when a signature is matched
func (engine *Engine) matchHandler(res *detect.Finding) {
	_ = engine.stats.Detections.Increment()
	engine.output <- res
	// TODO: the feedback here is enabled only in analyze, as it was causing a deadlock in the pipeline
	//       when the engine was blocked on sending a new event to the feedbacking signature.
	//       This is because the engine would eventually block on trying to to send
	//       a new event to the feedbacking signature. This would cause a deadlock
	//       there - propagating back to the engine and pipeline in general.
	// TODO2: Once we integrate the pipeline into analyze mode, we can remove this logic.
	if !(engine.config.Mode == ModeAnalyze) {
		return
		// next section is relevant only for  analyze
	}
	e, err := findings.FindingToEvent(res)
	if err != nil {
		logger.Errorw("Failed to convert finding to event, will not feedback", "err", err)
		return
	}
	prot := e.ToProtocol()
	engine.inputs.Tracee <- prot
}

// checkCompletion is a function that runs at the end of each input source
// closing tracee-rules if no more pending input sources exists
func (engine *Engine) checkCompletion() bool {
	if engine.inputs.Tracee == nil {
		engine.unloadAllSignatures()
		return true
	}
	return false
}

func (engine *Engine) processEvent(event protocol.Event) {
	engine.signaturesMutex.RLock()
	defer engine.signaturesMutex.RUnlock()

	_ = engine.stats.Events.Increment()

	// Pre-compute all selector patterns to avoid repeated struct creation
	sourceSelector := event.Headers.Selector.Source
	nameSelector := event.Headers.Selector.Name
	originSelector := event.Headers.Selector.Origin

	selectors := [4]detect.SignatureEventSelector{
		// Full selector
		{Source: sourceSelector, Name: nameSelector, Origin: originSelector},
		// Partial selector, select for all origins
		{Source: sourceSelector, Name: nameSelector, Origin: ALL_EVENT_ORIGINS},
		// Partial selector, select for event names
		{Source: sourceSelector, Name: ALL_EVENT_TYPES, Origin: originSelector},
		// Partial selector, select for all origins and event names
		{Source: sourceSelector, Name: ALL_EVENT_TYPES, Origin: ALL_EVENT_ORIGINS},
	}

	// Single loop through all selector patterns
	for i := range selectors {
		for _, s := range engine.signaturesIndex[selectors[i]] {
			engine.dispatchEvent(s, event)
		}
	}
}

// consumeSources starts consuming the input sources
// it runs continuously until stopped by the done channel
func (engine *Engine) consumeSources(ctx context.Context) {
	for {
		select {
		case event, ok := <-engine.inputs.Tracee:
			if !ok {
				// Skip signature signals if NoSignatures is enabled (signatures not initialized)
				if !engine.config.NoSignatures {
					engine.signaturesMutex.RLock()
					for sig := range engine.signatures {
						se, err := sig.GetSelectedEvents()
						if err != nil {
							logger.Errorw("Getting selected events: " + err.Error())
							continue
						}
						for _, sel := range se {
							if sel.Source == "tracee" {
								_ = sig.OnSignal(detect.SignalSourceComplete("tracee"))
								break
							}
						}
					}
					engine.signaturesMutex.RUnlock()
				}
				engine.inputs.Tracee = nil
				if engine.checkCompletion() {
					close(engine.output)
					return
				}

				continue
			}
			engine.processEvent(event)

		case <-ctx.Done():
			goto drain
		}
	}

drain:
	// drain and process all remaining events
	for {
		select {
		case event := <-engine.inputs.Tracee:
			engine.processEvent(event)

		default:
			return
		}
	}
}

func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
	// Early return if NoSignatures is enabled
	if engine.config.NoSignatures {
		return
	}

	if err := s.OnEvent(event); err != nil {
		if meta, metaErr := s.GetMetadata(); metaErr == nil {
			logger.Errorw("Processing event in signature", "signature", meta.Name, "error", err)
		} else {
			logger.Errorw("Processing event in signature", "signature", "unknown", "error", err, "metadata_error", metaErr)
		}
	}
}

// TODO: This method seems not to be used, let's confirm inside the team and remove it if not needed
// LoadSignature will call the internal signature loading logic and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature detect.Signature) (string, error) {
	id, err := engine.loadSignature(signature)
	if err != nil {
		return id, err
	}

	metadata, _ := signature.GetMetadata()
	logger.Debugw("Signature loaded at runtime", "signature", metadata.Name, "event", metadata.EventName, "id", metadata.ID)

	return id, nil
}

// loadSignature handles storing a signature in the Engine data structures
// It will return the signature ID as well as error.
func (engine *Engine) loadSignature(signature detect.Signature) (string, error) {
	metadata, err := signature.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("error getting metadata: %w", err)
	}
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return "", fmt.Errorf("error getting selected events for signature %s: %w", metadata.Name, err)
	}

	// Check if signature with this ID already exists
	engine.signaturesMutex.RLock()
	for existingSig := range engine.signatures {
		existingMetadata, _ := existingSig.GetMetadata()
		if existingMetadata.ID == metadata.ID {
			engine.signaturesMutex.RUnlock()
			// signature already exists
			return "", fmt.Errorf("failed to store signature: signature \"%s\" already loaded", metadata.Name)
		}
	}
	engine.signaturesMutex.RUnlock()

	signatureCtx := detect.SignatureContext{
		Callback: engine.matchHandler,
		Logger:   logger.Current(),
		GetDataSource: func(namespace, id string) (detect.DataSource, bool) {
			return engine.GetDataSource(namespace, id)
		},
	}

	// Skip signature initialization if NoSignatures is enabled
	if !engine.config.NoSignatures {
		if err := signature.Init(signatureCtx); err != nil {
			// failed to initialize
			return "", fmt.Errorf("error initializing signature %s: %w", metadata.Name, err)
		}
	}

	engine.signaturesMutex.Lock()
	engine.signatures[signature] = struct{}{}
	engine.signaturesMutex.Unlock()

	// insert in engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		if selectedEvent.Origin == "" {
			selectedEvent.Origin = ALL_EVENT_ORIGINS
		}
		if selectedEvent.Source == "" {
			logger.Errorw("Signature " + metadata.Name + " doesn't declare an input source")
		} else {
			engine.signaturesMutex.Lock()
			engine.signaturesIndex[selectedEvent] = append(engine.signaturesIndex[selectedEvent], signature)
			engine.signaturesMutex.Unlock()
		}
	}

	_ = engine.stats.Signatures.Increment()
	return metadata.ID, nil
}

// UnloadSignature will remove from Engine data structures the given signature and stop its handling goroutine
func (engine *Engine) UnloadSignature(signatureId string) error {
	var signature detect.Signature
	engine.signaturesMutex.RLock()
	for sig := range engine.signatures {
		metadata, _ := sig.GetMetadata()
		if metadata.ID == signatureId {
			signature = sig
			break
		}
	}
	engine.signaturesMutex.RUnlock()
	if signature == nil {
		return fmt.Errorf("could not find signature with ID: %v", signatureId)
	}
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return fmt.Errorf("failed to unload signature: %w", err)
	}
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	// remove from engine.signatures map
	_, ok := engine.signatures[signature]
	if ok {
		delete(engine.signatures, signature)
		defer func() {
			_ = engine.stats.Signatures.Decrement()
		}()
		defer signature.Close()

		metadata, _ := signature.GetMetadata()
		logger.Debugw("Signature unloaded at runtime", "signature", metadata.Name, "event", metadata.EventName, "id", metadata.ID)
	}
	// remove from engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		signatures := engine.signaturesIndex[selectedEvent]
		for i, sig := range signatures {
			metadata, _ := sig.GetMetadata()
			if metadata.ID == signatureId {
				// signature found, remove it
				signatures = append(signatures[:i], signatures[i+1:]...)
				engine.signaturesIndex[selectedEvent] = signatures
				break
			}
		}
	}
	return nil
}

// GetSelectedEvents returns the event selectors that are relevant to the currently loaded signatures
func (engine *Engine) GetSelectedEvents() []detect.SignatureEventSelector {
	res := make([]detect.SignatureEventSelector, 0)
	for k := range engine.signaturesIndex {
		res = append(res, k)
	}
	return res
}

func (engine *Engine) RegisterDataSource(dataSource detect.DataSource) error {
	engine.dataSourcesMutex.Lock()
	defer engine.dataSourcesMutex.Unlock()

	namespace := dataSource.Namespace()
	id := dataSource.ID()

	if _, ok := engine.dataSources[namespace]; !ok {
		engine.dataSources[namespace] = map[string]detect.DataSource{}
	}

	_, exists := engine.dataSources[namespace][id]
	if exists {
		return fmt.Errorf("failed to register data source: data source with name \"%s\" already exists in namespace \"%s\"", id, namespace)
	}
	engine.dataSources[namespace][id] = dataSource
	return nil
}

func (engine *Engine) GetDataSource(namespace string, id string) (detect.DataSource, bool) {
	engine.dataSourcesMutex.RLock()
	defer engine.dataSourcesMutex.RUnlock()

	namespaceCaches, ok := engine.dataSources[namespace]
	if !ok {
		return nil, false
	}

	cache, ok := namespaceCaches[id]

	return cache, ok
}
