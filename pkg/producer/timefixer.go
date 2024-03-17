package producer

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// A decorator producer that is responsible to fix events timestamps so they
// will match the ones received from the kernel.
// In practice, it means changing all times from being since epoch to monotonic
// times (since boot).
type TimeFixerProducer struct {
	internalProducer EventsProducer
	bootTime         int
}

func InitTimeFixerProducer(producer EventsProducer) *TimeFixerProducer {
	return &TimeFixerProducer{
		internalProducer: producer,
	}
}

func (tfixer *TimeFixerProducer) Produce() (trace.Event, error) {
	event, err := tfixer.internalProducer.Produce()
	if err != nil {
		return trace.Event{}, nil
	}
	switch events.ID(event.EventID) {
	case events.InitTraceeData:
		bootTime, err := parse.ArgVal[uint64](event.Args, "boot_time")
		if err != nil {
			return event, err
		}
		tfixer.bootTime = int(bootTime)
		fallthrough
	default:
		event.Timestamp -= tfixer.bootTime
	}
	return event, nil
}

func (tfixer *TimeFixerProducer) Done() <-chan struct{} {
	return tfixer.internalProducer.Done()
}
