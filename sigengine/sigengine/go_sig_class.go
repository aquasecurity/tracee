package sigengine

import "fmt"

var goSignatures map[string]GoSignature

type goSigClass struct {
}

// each go signature should implement the following interface
type GoSignature interface {
	GetMetadata() SigMetadata
	GetReqEvents() []RequestedEvent
	InitSig() error
	OnEvent(event Event) (SigResult, error)
	OnComplete() (SigResult, error)
}

func init() {
	goSignatures = make(map[string]GoSignature)
}

// New creates a new GoSigClass instance based on a given valid SignaturesConfig
func newGoSigClass() (*goSigClass, error) {
	// create GoSigClass
	s := &goSigClass{}

	return s, nil
}

func RegisterSignature(goSig GoSignature) {
	sigName := goSig.GetMetadata().Name
	goSignatures[sigName] = goSig

	// todo: register when gosigclass is initialized!
}

// implementation of getSigList() from signatureClass interface
func (g *goSigClass) getSigList() []SigMetadata {

	sigsMetadata := []SigMetadata{}

	for _, sig := range goSignatures {
		sigsMetadata = append(sigsMetadata, sig.GetMetadata())
	}

	return sigsMetadata
}

// implementation of getSigReqEvents() from signatureClass interface
func (g *goSigClass) getSigReqEvents(sigNames []string) (map[string][]RequestedEvent, error) {

	var exists bool
	var sig GoSignature
	// todo: fix naming conventions to camelCase
	sigsMapReqEvents := make(map[string][]RequestedEvent)

	for _, sigName := range sigNames {
		if sig, exists = goSignatures[sigName]; exists {
			sigsMapReqEvents[sigName] = sig.GetReqEvents()
		} else {
			return sigsMapReqEvents, fmt.Errorf("specified signature %s could not be found", sigName)
		}
	}

	return sigsMapReqEvents, nil
}

// implementation of initSigs() from signatureClass interface
func (g *goSigClass) initSigs(sigNames []string) error {

	var exists bool
	var sig GoSignature

	for _, sigName := range sigNames {
		if sig, exists = goSignatures[sigName]; exists {
			err := sig.InitSig()
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("specified signature %s could not be found", sigName)
		}
	}

	return nil
}

// implementation of onEvent() from signatureClass interface
func (g *goSigClass) onEvent(sigName string, event Event) (SigResult, error) {
	if sig, exists := goSignatures[sigName]; exists {
		return sig.OnEvent(event)
	} else {
		return SigResult{}, fmt.Errorf("specified signature %s could not be found", sigName)
	}
}

// implementation of onComplete() from signatureClass interface
func (g *goSigClass) onComplete(sigNames []string) (map[string]SigResult, error) {

	var exists bool
	var sig GoSignature
	sigsResults := make(map[string]SigResult)

	for _, sigName := range sigNames {
		if sig, exists = goSignatures[sigName]; exists {
			result, err := sig.OnComplete()
			if err != nil {
				return sigsResults, err
			}
			sigsResults[sigName] = result
		} else {
			return sigsResults, fmt.Errorf("specified signature %s could not be found", sigName)
		}
	}

	return sigsResults, nil
}
