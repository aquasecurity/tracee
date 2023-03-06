package pcaps

import (
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// Check pcaps.go for package description.

type PcapType uint

func (t *PcapType) String() string {
	switch *t {
	case Process:
		return "Process"
	case Container:
		return "Container"
	case Command:
		return "Command"
	case Single:
		return "Single"
	}

	return "None"
}

const (
	//
	// 1 (0001): process:   1 pcap file per process (default)
	// 2 (0010): container: 1 pcap file per container
	// 4 (0011): command:   1 pcap file per command
	// 8 (1000): single:    1 single pcap file for all
	//
	// or a combination:
	//
	// 3 (0011): process + container
	// 5 (0010): process + command
	// 6 (0110): container + command
	// 7 (0111): process + container + command
	//
	None      PcapType = 0x0
	Process   PcapType = 0x1
	Container PcapType = 0x2
	Command   PcapType = 0x4
	Single    PcapType = 0x8
)

type PcapOption uint32

const (
	Filtered PcapOption = 0x1
)

// Pcap is a representation of a pcap file
type Pcap struct {
	writtenPkts int              // packets written before next sync
	pcapType    PcapType         // Process, Container or Command
	pcapFile    *os.File         // pcap file descriptor
	pcapWriter  *pcapgo.NgWriter // pcap writer descriptor
}

func NewPcap(e *trace.Event, t PcapType) (*Pcap, error) {
	var err error

	p := &Pcap{
		pcapType: t,
	}

	p.pcapFile, p.pcapWriter, err = getPcapFileAndWriter(e, t)

	return p, errfmt.WrapError(err)
}

func (p *Pcap) write(event *trace.Event, payload []byte) error {
	info := gopacket.CaptureInfo{
		Timestamp:     time.Unix(0, int64(event.Timestamp)),
		CaptureLength: int(len(payload)),
		Length:        int(len(payload)),
	}

	if err := p.pcapWriter.WritePacket(info, payload); err != nil {
		return errfmt.WrapError(err)
	}
	p.writtenPkts++

	if p.writtenPkts >= flushAtPackets {
		if err := p.flush(); err != nil {
			logger.Errorw("Flushing pcap", "error", err)
		}
	}

	return nil
}

func (p *Pcap) flush() error {
	p.writtenPkts = 0
	return p.pcapWriter.Flush()
}

func (p *Pcap) close() error {
	if err := p.flush(); err != nil {
		logger.Errorw("Flushing pcap", "error", err)
	}
	return p.pcapFile.Close()
}
