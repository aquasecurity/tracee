// Package detect includes the "API" of the rule-engine and includes public facing types that consumers of the rule engine should work with
package detect

import (
	"github.com/aquasecurity/tracee/types/protocol"
)

// Signature is the basic unit of business logic for the rule-engine
type Signature interface {
	//GetMetadata allows the signature to declare information about itself
	GetMetadata() (SignatureMetadata, error)
	//GetSelectedEvents allows the signature to declare which events it subscribes to
	GetSelectedEvents() ([]SignatureEventSelector, error)
	//Init allows the signature to initialize its internal state
	Init(ctx SignatureContext) error
	//Close cleans the signature after Init operation
	Close()
	//OnEvent allows the signature to process events passed by the Engine. this is the business logic of the signature
	OnEvent(event protocol.Event) error
	//OnSignal allows the signature to handle lifecycle events of the signature
	OnSignal(signal Signal) error
}

type SignatureContext struct {
	Callback SignatureHandler
	Logger   Logger
}

// SignatureMetadata represents information about the signature
type SignatureMetadata struct {
	ID          string
	Version     string
	Name        string
	EventName   string
	Description string
	Tags        []string
	Properties  map[string]interface{}
}

// SignatureEventSelector represents events the signature is subscribed to
type SignatureEventSelector struct {
	Source string
	Name   string
	Origin string
}

// SignatureHandler is a callback function that reports a finding
type SignatureHandler func(found Finding)

// Signal is a generic lifecycle event for a signature
type Signal interface{}

// SignalSourceComplete signals that an input source the signature was subscribed to had ended
type SignalSourceComplete string

// Finding is the main output of a signature. It represents a match result for the signature business logic
type Finding struct {
	Data        map[string]interface{}
	Event       protocol.Event //Event is the causal event of the Finding
	SigMetadata SignatureMetadata
}

// Logger interface to inject in signatures
type Logger interface {
	Debugw(format string, v ...interface{})
	Infow(format string, v ...interface{})
	Warnw(format string, v ...interface{})
	Errorw(format string, v ...interface{})
}
