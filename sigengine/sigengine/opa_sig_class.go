package sigengine

type opaSigClass struct {
	//signatures []opaSignature
}

// New creates a new opaSigClass instance based on a given valid SignaturesConfig
func newOpaSigClass() (*opaSigClass, error) {
	//var err error

	// create OpaSigClass
	s := &opaSigClass{
		//config: cfg,
	}

	// todo: Initialize opaSigClass by getting all available opa signatures

	return s, nil
}

// implementation of getSigList() from signatureClass interface
func (o *opaSigClass) getSigList() []SigMetadata {
	return []SigMetadata{}
}

// implementation of getSigReqEvents() from signatureClass interface
func (o *opaSigClass) getSigReqEvents(sigNames []string) (map[string][]RequestedEvent, error) {
	return make(map[string][]RequestedEvent), nil
}

// implementation of initSigs() from signatureClass interface
func (o *opaSigClass) initSigs(sigNames []string) error {
	return nil
}

// implementation of onEvent() from signatureClass interface
func (o *opaSigClass) onEvent(sigName string, event Event) (SigResult, error) {
	// todo: run signatures in parallel when onEvent (with multiple signatures) is called!
	return SigResult{}, nil
}

// implementation of onComplete() from signatureClass interface
func (o *opaSigClass) onComplete(sigNames []string) (map[string]SigResult, error) {
	return make(map[string]SigResult), nil
}
