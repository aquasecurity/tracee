// Package types includes the "API" of the rule-engine and includes public facing types that consumers of the rule engine should work with
package types

// Signature is the basic unit of business logic for the rule-engine
type Signature interface {
	//GetMetadata allows the signature to declare information about itself
	GetMetadata() (SignatureMetadata, error)
	//GetSelectedEvents allows the signature to declare which events it subscribes to
	GetSelectedEvents() ([]SignatureEventSelector, error)
	//Init allows the signature to initialize its internal state
	Init(cb SignatureHandler) error
	//OnEvent allows the signature to process events passed by the Engine. this is the business logic of the signature
	OnEvent(event Event) error
	//OnSignal allows the signature to handle lifecycle events of the signature
	OnSignal(signal Signal) error
}

//SignatureMetadata represents information about the signature
type SignatureMetadata struct {
	ID          string                 `json:ID`
	Version     string                 `json:Version`
	Name        string                 `json:Name`
	Description string                 `json:Description`
	Tags        []string               `json:Tags`
	Properties  map[string]interface{} `json:Properties`
}

//SignatureEventSelector represents events the signature is subscribed to
type SignatureEventSelector struct {
	Source string
	Name   string
}

//SignatureHandler is a callback function that reports a finding
type SignatureHandler func(found Finding)

//Event is a generic event that the Engine can process
type Event interface{}

//Signal is a generic lifecycle event for a signature
type Signal interface{}

//SignalSourceComplete signals that an input source the signature was subscribed to has ended
type SignalSourceComplete string

//Finding is the main output of a signature. It represents a match result for the signature business logic
type Finding struct {
	Data        map[string]interface{} `json:Data`
	Context     Event                  `json:Context`
	SigMetadata SignatureMetadata      `json:SigMetadata`
}
