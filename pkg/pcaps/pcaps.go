package pcaps

import (
	"os"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// This is a big Pcaps struct holding caches for different types of Pcap files
// to be managed (pcap files per process, per containers and per commands). It
// would be hard to keep all possible pcap files open forever (as tracee might
// trace tons of processes, containers or commands).
//
// That is what the PcapCache struct is for. It keeps Pcap files and maintain
// those Pcap files cached while they're still being used.
//
// At the end we have the Pcap struct itself. It describes a pcap file being
// kept opened on behalf of a process, a container or a command.
//
// NOTE: Pcaps is not thread safe, should be called from a single routine.
//

// Pcaps holds all Pcap for different PcapTypes
type Pcaps struct {
	pcapCaches map[PcapType]*PcapCache
}

func New(simple config.PcapsConfig, output *os.File) (*Pcaps, error) {
	var err error

	cfg := configToPcapType(simple)

	// initialize all keys first
	caches := map[PcapType]*PcapCache{
		Single:    nil,
		Process:   nil,
		Container: nil,
		Command:   nil,
	}

	initializeGlobalVars(output)

	for t := range caches {
		if cfg&t == t { // if type was requested, init its cache
			logger.Debugw("pcap enabled: " + t.String())
			caches[t], err = newPcapCache(t)
			if err != nil {
				return nil, errfmt.WrapError(err)
			}
		} else {
			// remove keys that were not requested
			delete(caches, t)
		}
	}

	return &Pcaps{pcapCaches: caches}, nil
}

// Write writes a packet to all opened pcap files from all supported pcap types
func (p *Pcaps) Write(event *trace.Event, payload []byte) error {
	// sanity check
	if events.ID(event.EventID) != events.NetPacketCapture {
		return errfmt.Errorf("wrong event type given to pcap")
	}

	for k := range p.pcapCaches {
		item, err := p.pcapCaches[k].get(event)
		if err != nil {
			return errfmt.WrapError(err)
		}
		err = item.write(event, payload)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// Destroy destroys all opened pcap files from all supported pcap types
func (p *Pcaps) Destroy() error {
	for k := range p.pcapCaches {
		err := p.pcapCaches[k].destroy()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}
