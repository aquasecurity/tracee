package ebpf

import (
	"context"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/types/trace"
)

// initDerivationTable initializes tracee's events.DerivationTable.
// we declare for each Event (represented through it's ID) to which other
// events it can be derived and the corresponding function to derive into that Event.
func (t *Tracee) initDerivationTable() error {
	// sanity check for containers dependency
	if t.containers == nil {
		return fmt.Errorf("nil tracee containers")
	}

	t.eventDerivations = events.DerivationTable{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:  t.events[events.ContainerCreate].submit,
				Function: derive.ContainerCreate(t.containers),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:  t.events[events.ContainerRemove].submit,
				Function: derive.ContainerRemoved(t.containers),
			},
		},
		events.PrintSyscallTable: {
			events.HookedSyscalls: {
				Enabled:  t.events[events.PrintSyscallTable].submit,
				Function: derive.DetectHookedSyscall(t.kernelSymbols),
			},
		},
		events.DnsRequest: {
			events.NetPacket: {
				Enabled:  t.events[events.NetPacket].submit,
				Function: derive.NetPacket(),
			},
		},
		events.DnsResponse: {
			events.NetPacket: {
				Enabled:  t.events[events.NetPacket].submit,
				Function: derive.NetPacket(),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:  t.events[events.HookedSeqOps].submit,
				Function: derive.HookedSeqOps(t.kernelSymbols),
			},
		},
	}

	return nil
}

// deriveEvents is the derivation pipeline stage
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case event := <-in:
				out <- event

				// Derive event before parse its arguments
				derivatives, errors := events.Derive(*event, t.eventDerivations)

				for _, err := range errors {
					t.handleError(err)
				}

				for _, derivative := range derivatives {
					out <- &derivative
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}
