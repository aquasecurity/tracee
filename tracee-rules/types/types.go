// Package types includes the "API" of the rule-engine and includes public facing types that consumers of the rule engine should work with
package types

// Signature is the basic unit of business logic for the rule-engine
type Signature interface {
	//GetMetadata allows the signature to declare information about itself
	GetMetadata() SignatureMetadata
	//GetSelectedEvents allows the signature to declare which events it subscribes to
	GetSelectedEvents() []SignatureEventSelector
	//Init allows the signature to initialize its internal state
	Init(cb SignatureHandler) error
	//OnEvent allows the signature to process events passed by the Engine. this is the business logic of the signature
	OnEvent(event Event) error
	//OnSignal allows the signature to handle lifecycle events of the signature
	OnSignal(signal Signal) error
}

//SignatureMetadata represents information about the signature
type SignatureMetadata struct {
	Name        string
	Description string
	Tags        []string
	Properties  map[string]interface{}
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
	Data      []FindingData
	Context   Event
	Signature Signature
}

//FindingData is a paticular piece if data that corresponds to a Finding
type FindingData struct {
	Type       string
	Properties map[string]interface{}
}

//TraceeEvent represents a Traee Event and is used for Tracee input source
//It should match the Event struct declared in Tracee
type TraceeEvent struct {
	Timestamp           float64               `json:"timestamp"`
	ProcessID           int                   `json:"processId"`
	ThreadID            int                   `json:"threadId"`
	ParentProcessID     int                   `json:"parentProcessId"`
	HostProcessID       int                   `json:"hostProcessId"`
	HostThreadID        int                   `json:"hostThreadId"`
	HostParentProcessID int                   `json:"hostParentProcessId"`
	UserID              int                   `json:"userId"`
	MountNS             int                   `json:"mountNamespace"`
	PIDNS               int                   `json:"pidNamespace"`
	ProcessName         string                `json:"processName"`
	HostName            string                `json:"hostName"`
	EventID             int                   `json:"eventId,string"`
	EventName           string                `json:"eventName"`
	ArgsNum             int                   `json:"argsNum"`
	ReturnValue         int                   `json:"returnValue"`
	Args                []TraceeEventArgument `json:"args"`
}

//TraceeEventArgument is a key-value pair that represents an argument in a Tracee Event
type TraceeEventArgument struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}
