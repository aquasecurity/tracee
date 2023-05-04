package printer

import (
	"github.com/aquasecurity/tracee/types/trace"
)

// Broadcast is a printer that broadcasts events to multiple printers
type Broadcast struct {
	eventsChan []chan trace.Event
	done       chan struct{}
}

// NewBroadcast creates a new Broadcast printer
func NewBroadcast(printers []EventPrinter) *Broadcast {
	eventsChan := make([]chan trace.Event, 0, len(printers))
	done := make(chan struct{})

	for _, printer := range printers {
		// we use a buffered channel to avoid blocking the event channel,
		// we match the size of ChanEvents buffer
		eventChan := make(chan trace.Event, 1000)
		eventsChan = append(eventsChan, eventChan)

		go startPrinter(done, eventChan, printer)
	}

	return &Broadcast{
		eventsChan: eventsChan,
		done:       done,
	}
}

// Print broadcasts the event to all printers
func (b *Broadcast) Print(event trace.Event) {
	for _, c := range b.eventsChan {
		// we are blocking here if the printer is not consuming events fast enough
		c <- event
	}
}

// Close closes Broadcast printer
func (b *Broadcast) Close() {
	close(b.done)
}

func startPrinter(done chan struct{}, c chan trace.Event, p EventPrinter) {
	// Print the preamble and start event channel reception
	p.Preamble()

	for {
		select {
		case <-done:
			return
		case event := <-c:
			p.Print(event)
		}
	}
}
