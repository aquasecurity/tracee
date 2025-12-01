package printer

import (
	"context"

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

// newBroadcast creates a new Broadcast printer
func newBroadcast(destinationConfigs []config.Destination) (*Broadcast, error) {
	b := &Broadcast{DestinationConfigs: destinationConfigs}
	return b, b.Init()
}

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

func (b *Broadcast) Preamble() {
	for _, p := range b.printers {
		p.Preamble()
	}
}

// Print broadcasts the event to all printers
func (b *Broadcast) Print(event *pb.Event) {
	for _, p := range b.printers {
		// we are blocking here if the printer is not consuming events fast enough
		p.Print(event)
	}
}

func (b *Broadcast) Epilogue(stats metrics.Stats) {
	for _, p := range b.printers {
		p.Epilogue(stats)
	}
}

func (b *Broadcast) FromStream(ctx context.Context, stream *streams.Stream) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-stream.ReceiveEvents():
			b.Print(e)
		}
	}
}

func (b *Broadcast) Kind() string {
	return "broadcast"
}

// Close closes Broadcast printer
func (b *Broadcast) Close() {
	for _, p := range b.printers {
		p.Close()
	}
}
