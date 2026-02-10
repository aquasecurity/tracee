package printer

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/streams"
)

// Broadcast is a printer that broadcasts events to multiple printers
type Broadcast struct {
	DestinationConfigs []config.Destination
	printers           []EventPrinter
	containerMode      config.ContainerMode
}

// newBroadcast creates a new Broadcast printer that sends events to multiple destinations.
func newBroadcast(destinationConfigs []config.Destination) (*Broadcast, error) {
	b := &Broadcast{DestinationConfigs: destinationConfigs}
	return b, b.Init()
}

// Init initializes the Broadcast printer by creating individual printers for each destination.
func (b *Broadcast) Init() error {
	printers := make([]EventPrinter, 0, len(b.DestinationConfigs))

	for _, dstConfig := range b.DestinationConfigs {
		p, err := newSinglePrinter(dstConfig)
		if err != nil {
			return err
		}

		printers = append(printers, p)
	}

	b.printers = printers

	return nil
}

// Preamble calls Preamble on all underlying printers.
func (b *Broadcast) Preamble() {
	for _, p := range b.printers {
		p.Preamble()
	}
}

// Print broadcasts the event to all underlying printers.
// Note: This method blocks if any printer is not consuming events fast enough.
func (b *Broadcast) Print(event *pb.Event) {
	for _, p := range b.printers {
		// we are blocking here if the printer is not consuming events fast enough
		p.Print(event)
	}
}

// Epilogue calls Epilogue on all underlying printers with the given stats.
func (b *Broadcast) Epilogue(stats metrics.Stats) {
	for _, p := range b.printers {
		p.Epilogue(stats)
	}
}

// FromStream receives events from the stream and broadcasts them to all underlying printers.
// It runs until the stream's event channel is closed, ensuring all events are drained during shutdown.
func (b *Broadcast) FromStream(stream *streams.Stream) {
	for e := range stream.ReceiveEvents() {
		b.Print(e)
	}
}

// Kind returns the kind of the Broadcast printer.
func (b *Broadcast) Kind() string {
	return "broadcast"
}

// Close closes all underlying printers and releases their resources.
func (b *Broadcast) Close() {
	for _, p := range b.printers {
		p.Close()
	}
}
