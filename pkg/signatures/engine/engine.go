package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/metrics"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

const ALL_EVENT_ORIGINS = "*"
const EVENT_CONTAINER_ORIGIN = "container"
const EVENT_HOST_ORIGIN = "host"
const ALL_EVENT_TYPES = "*"

// Config defines the engine's configurable values
type Config struct {
	// Enables the signatures engine to run in the events pipeline
	Enabled             bool
	SignatureBufferSize uint
	Signatures          []detect.Signature
}

// Engine is a signatures-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	signatures      map[detect.Signature]chan protocol.Event
	signaturesIndex map[detect.SignatureEventSelector][]detect.Signature
	signaturesMutex sync.RWMutex
	inputs          EventSources
	output          chan detect.Finding
	waitGroup       sync.WaitGroup
	config          Config
	stats           metrics.Stats
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
func NewEngine(config Config, sources EventSources, output chan detect.Finding) (*Engine, error) {
	if sources.Tracee == nil || output == nil {
		return nil, fmt.Errorf("nil input received")
	}
	engine := Engine{}
	engine.waitGroup = sync.WaitGroup{}

	engine.inputs = sources
	engine.output = output
	engine.config = config
	engine.signaturesMutex.Lock()
	engine.signatures = make(map[detect.Signature]chan protocol.Event)
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
	engine.signaturesMutex.Unlock()
	for _, sig := range config.Signatures {
		_, err := engine.loadSignature(sig)
		if err != nil {
			logger.Errorw("Loading signature: " + err.Error())
		}
	}
	return &engine, nil
}

// StartPipeline receives an input channel, and returns an output channel
// allowing the signatures engine to be used in the events pipeline
func StartPipeline(ctx context.Context, cfg Config, input chan protocol.Event) <-chan detect.Finding {
	output := make(chan detect.Finding)

	source := EventSources{Tracee: input}
	engine, err := NewEngine(cfg, source, output)
	if err != nil {
		logger.Fatalw("Error creating engine: " + err.Error())
	}

	go func() {
		defer close(output)
		engine.Start(ctx)
	}()

	return output
}

// signatureStart is the signature handling business logics.
func signatureStart(signature detect.Signature, c chan protocol.Event, wg *sync.WaitGroup) {
	wg.Add(1)
	for e := range c {
		if err := signature.OnEvent(e); err != nil {
			meta, _ := signature.GetMetadata()
			logger.Errorw("Handling event by signature " + meta.Name + ": " + err.Error())
		}
	}
	wg.Done()
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(ctx context.Context) {
	defer engine.unloadAllSignatures()
	engine.signaturesMutex.RLock()
	for s, c := range engine.signatures {
		go signatureStart(s, c, &engine.waitGroup)
	}
	engine.signaturesMutex.RUnlock()
	engine.consumeSources(ctx)
}

func (engine *Engine) unloadAllSignatures() {
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	for sig, c := range engine.signatures {
		sig.Close()
		close(c)
		delete(engine.signatures, sig)
	}
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
}

// matchHandler is a function that runs when a signature is matched
func (engine *Engine) matchHandler(res detect.Finding) {
	_ = engine.stats.Detections.Increment()
	engine.output <- res
}

// checkCompletion is a function that runs at the end of each input source
// closing tracee-rules if no more pending input sources exists
func (engine *Engine) checkCompletion() bool {
	if engine.inputs.Tracee == nil {
		engine.unloadAllSignatures()
		engine.waitGroup.Wait()
		return true
	}
	return false
}

// consumeSources starts consuming the input sources
// it runs continuously until stopped by the done channel
func (engine *Engine) consumeSources(ctx context.Context) {
	for {
		select {
		case event, ok := <-engine.inputs.Tracee:
			if !ok {
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
				engine.inputs.Tracee = nil
				if engine.checkCompletion() {
					return
				}
			} else {
				engine.signaturesMutex.RLock()
				signatureSelector := detect.SignatureEventSelector{
					Origin: event.Headers.Selector.Origin,
					Name:   event.Headers.Selector.Name,
					Source: event.Headers.Selector.Source,
				}
				source := signatureSelector.Source
				_ = engine.stats.Events.Increment()

				//Check the selector for every case and partial case

				//Match full selector
				for _, s := range engine.signaturesIndex[signatureSelector] {
					engine.dispatchEvent(s, event)
				}

				//Match partial selector, select for all origins
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: source, Name: signatureSelector.Name, Origin: ALL_EVENT_ORIGINS}] {
					engine.dispatchEvent(s, event)
				}

				//Match partial selector, select for event names
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: source, Name: ALL_EVENT_TYPES, Origin: signatureSelector.Origin}] {
					engine.dispatchEvent(s, event)
				}

				//Match partial selector, select for all origins and event names
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: source, Name: ALL_EVENT_TYPES, Origin: ALL_EVENT_ORIGINS}] {
					engine.dispatchEvent(s, event)
				}
				engine.signaturesMutex.RUnlock()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
	engine.signatures[s] <- event
}

// LoadSignature will call the internal signature loading logic and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature detect.Signature) (string, error) {
	id, err := engine.loadSignature(signature)
	if err != nil {
		return id, err
	}
	engine.signaturesMutex.RLock()
	go signatureStart(signature, engine.signatures[signature], &engine.waitGroup)
	engine.signaturesMutex.RUnlock()

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
	// insert in engine.signatures map
	engine.signaturesMutex.RLock()
	if engine.signatures[signature] != nil {
		engine.signaturesMutex.RUnlock()
		// signature already exists
		return "", fmt.Errorf("failed to store signature: signature \"%s\" already loaded", metadata.Name)
	}
	engine.signaturesMutex.RUnlock()
	if err := signature.Init(detect.SignatureContext{Callback: engine.matchHandler, Logger: logger.Current()}); err != nil {
		//failed to initialize
		return "", fmt.Errorf("error initializing signature %s: %w", metadata.Name, err)
	}
	c := make(chan protocol.Event, engine.config.SignatureBufferSize)
	engine.signaturesMutex.Lock()
	engine.signatures[signature] = c
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
	c, ok := engine.signatures[signature]
	if ok {
		delete(engine.signatures, signature)
		defer func() {
			_ = engine.stats.Signatures.Decrement()
		}()
		defer signature.Close()
		defer close(c)
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
