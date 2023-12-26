// Package detect includes the "API" of the rule-engine and includes public facing types that consumers of the rule engine should work with
package detect

import (
	"errors"

	"github.com/aquasecurity/tracee/types/protocol"
)

// Signature is the basic unit of business logic for the rule-engine
type Signature interface {
	// GetMetadata allows the signature to declare information about itself
	GetMetadata() (SignatureMetadata, error)
	// GetSelectedEvents allows the signature to declare which events it subscribes to
	GetSelectedEvents() ([]SignatureEventSelector, error)
	// Init allows the signature to initialize its internal state
	Init(ctx SignatureContext) error
	// Close cleans the signature after Init operation
	Close()
	// OnEvent allows the signature to process events passed by the Engine. this is the business logic of the signature
	OnEvent(event protocol.Event) error
	// OnSignal allows the signature to handle lifecycle events of the signature
	OnSignal(signal Signal) error
}

type SignatureContext struct {
	Callback      SignatureHandler
	Logger        Logger
	GetDataSource func(namespace string, id string) (DataSource, bool)
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
type SignatureHandler func(found *Finding)

// Signal is a generic lifecycle event for a signature
type Signal interface{}

// SignalSourceComplete signals that an input source the signature was subscribed to had ended
type SignalSourceComplete string

// Logger interface to inject in signatures
type Logger interface {
	Debugw(format string, v ...interface{})
	Infow(format string, v ...interface{})
	Warnw(format string, v ...interface{})
	Errorw(format string, v ...interface{})
}

type DataSource interface {
	// Get a value from the data source. Make sure the key matches one of the keys allowed in Keys.
	// The following errors should be returned for the appropriate cases:
	//
	//	- ErrDataNotFound - When the key does not match to any existing data
	//	- ErrKeyNotSupported - When the key used does not match to a support key
	//	- Otherwise errors may vary.
	Get(interface{}) (map[string]interface{}, error)
	// Version of the data fetched. Whenever the schema has a breaking change the version should be incremented.
	// Consumers of the data source should verify they are running against a support version before using it.
	Version() uint
	// The types of keys the data source supports.
	Keys() []string
	// JSON Schema of the data source's result. All Get results should conform to the schema described.
	Schema() string
	// Namespace of the data source (to avoid ID collisions)
	Namespace() string
	// ID of the data source, any unique name works.
	ID() string
}

var ErrDataNotFound = errors.New("requested data was not found")
var ErrKeyNotSupported = errors.New("queried key is not supported")
var ErrFailedToUnmarshal = errors.New("given value could not be unmarshaled")

type WriteableDataSource interface {
	DataSource
	// Write values to keys in the data source. The values may not strictly match the schema defined
	// in the data source, however the implementation must be able to unmarshal it successfully to some form
	// where it can be eventually represented by the schema.
	//
	// The following errors should be returned for the appropriate cases:
	//
	// - ErrKeyNotSupported - When a given key does not match to supported key type
	// - ErrFailedToUnmarshal - When a value given could not be unmarshalled to an expected type
	// - Otherwise errors may vary.
	Write(data map[interface{}]interface{}) error
	// The types of values the data source supports writing.
	Values() []string
}
