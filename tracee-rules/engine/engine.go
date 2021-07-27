package engine

import (
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	filter "github.com/aquasecurity/tracee/tracee-rules/signatures/filters"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// Engine is a rule-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	logger          log.Logger
	signatures      map[types.Signature]chan types.Event
	signaturesMutex sync.RWMutex
	inputs          EventSources
	output          chan types.Finding
	filterManager   *filter.FilterManager
}

//EventSources is a bundle of input sources used to configure the Engine
type EventSources struct {
	Tracee chan types.Event
}

// NewEngine creates a new rules-engine with the given arguments
// inputs and outputs are given as channels created by the consumer
func NewEngine(sigs []types.Signature, sources EventSources, output chan types.Finding, logWriter io.Writer) (*Engine, error) {
	if sources.Tracee == nil || output == nil || logWriter == nil {
		return nil, fmt.Errorf("nil input received")
	}
	engine := Engine{}
	engine.logger = *log.New(logWriter, "", 0)
	engine.inputs = sources
	engine.output = output
	engine.signaturesMutex.Lock()
	engine.signatures = make(map[types.Signature]chan types.Event)
	engine.filterManager, _ = filter.NewFilterManager(&engine.logger, sigs)
	engine.signaturesMutex.Unlock()
	for _, sig := range sigs {
		engine.signaturesMutex.Lock()
		engine.signatures[sig] = make(chan types.Event)
		engine.signaturesMutex.Unlock()
		initError := sig.Init(engine.matchHandler)
		if initError != nil {
			meta, getMetaDataError := sig.GetMetadata()
			if getMetaDataError != nil {
				engine.logger.Printf("error getting metadata: %v", getMetaDataError)
			}
			engine.logger.Printf("error initializing signature %s: %v", meta.Name, initError)
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
func signatureStart(signature types.Signature, c chan types.Event) {
	for e := range c {
		if err := signature.OnEvent(e); err != nil {
			meta, _ := signature.GetMetadata()
			log.Printf("error handling event by signature %s: %v", meta.Name, err)
		}
	}
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(done chan bool) {
	defer engine.unloadAllSignatures()
	engine.signaturesMutex.RLock()
	for s, c := range engine.signatures {
		go signatureStart(s, c)
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
	engine.filterManager.RemoveAllSignatures()
}

// matchHandler is a function that runs when a signature is matched
func (engine *Engine) matchHandler(res types.Finding) {
	engine.output <- res
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
						engine.logger.Printf("%v", err)
						continue
					}
					for _, sel := range se {
						if sel.Source == "tracee" {
							_ = sig.OnSignal(types.SignalSourceComplete("tracee"))
							break
						}
					}
				}
				engine.signaturesMutex.RUnlock()
				engine.inputs.Tracee = nil
			} else if event != nil {
				engine.signaturesMutex.RLock()
				traceeEvt, ok := event.(tracee.Event)
				if !ok {
					engine.logger.Printf("invalid event received (should be of type tracee.Event)")
					engine.signaturesMutex.RUnlock()
					continue
				}
				filteredSignatures, _ := engine.filterManager.GetFilteredSignatures(traceeEvt)
				for _, signature := range filteredSignatures {
					engine.signatures[signature] <- traceeEvt
				}
				engine.signaturesMutex.RUnlock()
			}
		case <-done:
			return
		}
	}
}

//LoadSignature will store in Engine data structures the given signature and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature types.Signature) (string, error) {
	metadata, _ := signature.GetMetadata()
	// insert in engine.signatures map
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	if engine.signatures[signature] != nil {
		// signature already exists
		return metadata.ID, nil
	}
	c := make(chan types.Event)
	engine.signatures[signature] = c
	engine.filterManager.AddSignature(signature)

	if err := signature.Init(engine.matchHandler); err != nil {
		engine.logger.Printf("error initializing signature %s: %v", metadata.Name, err)

	}
	go signatureStart(signature, c)
	return metadata.ID, nil
}

//UnloadSignature will remove from Engine data structures the given signature and stop its handling goroutine
func (engine *Engine) UnloadSignature(signatureId string) error {
	var signature types.Signature
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
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	// remove from engine.signatures map
	c, ok := engine.signatures[signature]
	if ok {
		delete(engine.signatures, signature)
		defer signature.Close()
		defer close(c)

		engine.filterManager.RemoveSignature(signature)
	}
	return nil
}
