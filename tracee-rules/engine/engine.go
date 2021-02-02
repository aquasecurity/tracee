package engine

import (
	"io"
	"log"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

// Engine is a rule-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	logger          log.Logger
	signatures      map[types.Signature]chan types.Event
	signaturesIndex map[types.SignatureEventSelector][]types.Signature
	inputs          EventSources
	output          chan types.Finding
}

//EventSources is a bundle of input sources used to configure the Engine
type EventSources struct {
	Tracee chan types.Event
}

// NewEngine creates a new rules-engine with the given arguments
// inputs and outputs are given as channels created by the consumer
func NewEngine(sigs []types.Signature, sources EventSources, output chan types.Finding, logWriter io.Writer) *Engine {
	engine := Engine{}
	engine.logger = *log.New(logWriter, "", 0)
	engine.inputs = sources
	engine.output = output
	engine.signatures = make(map[types.Signature]chan types.Event)
	engine.signaturesIndex = make(map[types.SignatureEventSelector][]types.Signature)
	for _, sig := range sigs {
		engine.signatures[sig] = make(chan types.Event)
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
				es.Name = "*"
			}
			if es.Source == "" {
				engine.logger.Printf("signature %s doesn't declare an input source", meta.Name)
			} else {
				engine.signaturesIndex[es] = append(engine.signaturesIndex[es], sig)
			}
		}
		err = sig.Init(engine.matchHandler)
		if err != nil {
			engine.logger.Printf("error initializing signature %s: %v", meta.Name, err)
			continue
		}
	}
	return &engine
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(done chan bool) {
	go engine.consumeSources(done)
	for s, c := range engine.signatures {
		defer close(c)
		go func(s types.Signature, c chan types.Event) {
			for e := range c {
				err := s.OnEvent(e)
				if err != nil {
					meta, _ := s.GetMetadata()
					log.Printf("error handling event by signature %s: %v", meta.Name, err)
				}
			}
		}(s, c)
	}
	<-done
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
				engine.inputs.Tracee = nil
			} else if event != nil {
				for _, s := range engine.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: event.(tracee.Event).EventName}] {
					engine.signatures[s] <- event
				}
				for _, s := range engine.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: "*"}] {
					engine.signatures[s] <- event
				}
			}
		case <-done:
			return
		}
	}
}
