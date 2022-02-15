package engine

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/pkg/rules/metrics"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

const ALL_EVENT_ORIGINS = "*"
const EVENT_CONTAINER_ORIGIN = "container"
const EVENT_HOST_ORIGIN = "host"
const ALL_EVENT_TYPES = "*"

// Config defines the engine's configurable values
type Config struct {
	SignatureBufferSize uint
}

// Engine is a rule-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	logger          log.Logger
	signatures      map[detect.Signature]chan protocol.Event
	signaturesIndex map[detect.SignatureEventSelector][]detect.Signature
	signaturesMutex sync.RWMutex
	inputs          EventSources
	output          chan detect.Finding
	waitGroup       sync.WaitGroup
	config          Config
	stats           metrics.Stats
}

//EventSources is a bundle of input sources used to configure the Engine
type EventSources struct {
	Tracee chan protocol.Event
}

func (e *Engine) Stats() *metrics.Stats {
	return &e.stats
}

// NewEngine creates a new rules-engine with the given arguments
// inputs and outputs are given as channels created by the consumer
func NewEngine(sigs []detect.Signature, sources EventSources, output chan detect.Finding, logWriter io.Writer, config Config) (*Engine, error) {
	if sources.Tracee == nil || output == nil || logWriter == nil {
		return nil, fmt.Errorf("nil input received")
	}
	engine := Engine{}
	engine.waitGroup = sync.WaitGroup{}
	engine.logger = *log.New(logWriter, "", 0)
	engine.inputs = sources
	engine.output = output
	engine.config = config
	engine.signaturesMutex.Lock()
	engine.signatures = make(map[detect.Signature]chan protocol.Event)
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
	engine.signaturesMutex.Unlock()
	for _, sig := range sigs {
		engine.signaturesMutex.Lock()
		engine.signatures[sig] = make(chan protocol.Event, engine.config.SignatureBufferSize)
		engine.signaturesMutex.Unlock()
		meta, err := sig.GetMetadata()
		if err != nil {
			engine.logger.Printf("error getting metadata: %v", err)
			continue
		}
		se, err := sig.GetSelectedEvents()
		if err != nil {
			engine.logger.Printf("error getting selected events for signature %s: %v", meta.Name, err)
			continue
		}
		for _, es := range se {
			if es.Name == "" {
				es.Name = ALL_EVENT_TYPES
			}
			if es.Origin == "" {
				es.Origin = ALL_EVENT_ORIGINS
			}
			if es.Source == "" {
				engine.logger.Printf("signature %s doesn't declare an input source", meta.Name)
			} else {
				engine.signaturesMutex.Lock()
				engine.signaturesIndex[es] = append(engine.signaturesIndex[es], sig)
				engine.signaturesMutex.Unlock()
			}
		}
		err = sig.Init(engine.matchHandler)
		if err != nil {
			engine.logger.Printf("error initializing signature %s: %v", meta.Name, err)
			continue
		}
	}
	engine.signaturesMutex.RLock()
	lenSigs := len(engine.signatures)
	engine.signaturesMutex.RUnlock()
	if len(sigs) != lenSigs {
		return nil, errors.New("one or more signatures are not uniquely identifiable")
	}
	return &engine, nil
}

// signatureStart is the signature handling business logics.
func signatureStart(signature detect.Signature, c chan protocol.Event, wg *sync.WaitGroup) {
	wg.Add(1)
	for e := range c {
		if err := signature.OnEvent(e); err != nil {
			meta, _ := signature.GetMetadata()
			log.Printf("error handling event by signature %s: %v", meta.Name, err)
		}
	}
	wg.Done()
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(done chan bool) {
	defer engine.unloadAllSignatures()
	engine.signaturesMutex.RLock()
	for s, c := range engine.signatures {
		go signatureStart(s, c, &engine.waitGroup)
	}
	engine.signaturesMutex.RUnlock()
	engine.consumeSources(done)
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
	engine.stats.Detections.Increment()
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
func (engine *Engine) consumeSources(done <-chan bool) {
	for {
		select {
		case event, ok := <-engine.inputs.Tracee:
			if !ok {
				engine.signaturesMutex.RLock()
				for sig := range engine.signatures {
					se, err := sig.GetSelectedEvents()
					if err != nil {
						engine.logger.Printf("error getting selected events: %v", err)
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
				signatureSelector, err := eventSignatureSelector(event)

				if err != nil {
					engine.logger.Printf("invalid event received (should be of type %s)", trace.EventContentType)
					engine.signaturesMutex.RUnlock()
					continue
				}
				engine.stats.Events.Increment()

				for _, s := range engine.signaturesIndex[signatureSelector] {
					engine.dispatchEvent(s, event)
				}
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: "tracee", Name: signatureSelector.Name, Origin: ALL_EVENT_ORIGINS}] {
					engine.dispatchEvent(s, event)
				}
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: "tracee", Name: ALL_EVENT_TYPES, Origin: signatureSelector.Origin}] {
					engine.dispatchEvent(s, event)
				}
				for _, s := range engine.signaturesIndex[detect.SignatureEventSelector{Source: "tracee", Name: ALL_EVENT_TYPES, Origin: ALL_EVENT_ORIGINS}] {
					engine.dispatchEvent(s, event)
				}
				engine.signaturesMutex.RUnlock()
			}
		case <-done:
			return
		}
	}
}

func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
	engine.signatures[s] <- event
}

//LoadSignature will store in Engine data structures the given signature and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature detect.Signature) (string, error) {
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return "", fmt.Errorf("failed to store signature: %w", err)
	}
	metadata, _ := signature.GetMetadata()
	// insert in engine.signatures map
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	if engine.signatures[signature] != nil {
		// signature already exists
		return metadata.ID, nil
	}
	c := make(chan protocol.Event, engine.config.SignatureBufferSize)
	engine.signatures[signature] = c

	// insert in engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		if selectedEvent.Origin == "" {
			selectedEvent.Origin = ALL_EVENT_ORIGINS
		}
		if selectedEvent.Source == "" {
			engine.logger.Printf("signature %s doesn't declare an input source", metadata.Name)
		} else {
			engine.signaturesIndex[selectedEvent] = append(engine.signaturesIndex[selectedEvent], signature)
		}
	}
	if err := signature.Init(engine.matchHandler); err != nil {
		engine.logger.Printf("error initializing signature %s: %v", metadata.Name, err)

	}
	engine.stats.Signatures.Increment()
	go signatureStart(signature, c, &engine.waitGroup)
	return metadata.ID, nil
}

//UnloadSignature will remove from Engine data structures the given signature and stop its handling goroutine
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
		defer engine.stats.Signatures.Decrement()
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

func eventSignatureSelector(event protocol.Event) (detect.SignatureEventSelector, error) {
	origin := event.Origin()
	contentType := event.ContentType()
	if !(strings.HasPrefix(origin, trace.EventSource) && strings.HasPrefix(contentType, trace.EventContentType)) {
		return detect.SignatureEventSelector{}, fmt.Errorf("the signature selector could not be determined since the event isn't a tracee event")
	}

	return detect.SignatureEventSelector{
		Origin: strings.TrimPrefix(origin, trace.EventSource+"/"),
		Name:   strings.TrimPrefix(contentType, trace.EventContentType+"-"),
		Source: "tracee",
	}, nil
}

// GetSelectedEvents returns the event selectors that are relevant to the currently loaded signatures
func (engine *Engine) GetSelectedEvents() []detect.SignatureEventSelector {
	res := make([]detect.SignatureEventSelector, 0)
	for k := range engine.signaturesIndex {
		res = append(res, k)
	}
	return res
}
