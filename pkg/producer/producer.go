package producer

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

// EventsProducer is a type that is able to generate events
type EventsProducer interface {
	// Produce produces a single event.
	// Return io.EOF for end of events stream.
	Produce() (trace.Event, error)
}

func New(cfg *config.ProducerConfig) (EventsProducer, error) {
	var res EventsProducer
	kind := cfg.Kind

	if cfg.InputSource == nil {
		return res, errfmt.Errorf("input source is not set")
	}

	switch kind {
	case "json":
		return newJsonEventProducer(cfg.InputSource), nil
	case "rego":
	default:
		return nil, fmt.Errorf("unsuupported producer kind - %s", cfg.Kind)
	}
	return nil, fmt.Errorf("unsuupported producer kind - %s", cfg.Kind)
}
