package pcaps

import (
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
	}

	return "None"
}

const (
	//
	// 1 (001): process:   1 pcap file per process (default)
	// 2 (010): container: 1 pcap file per container
	// 4 (011): command:   1 pcap file per command
	//
	// or a combination:
	//
	// 3 (011): process + container
	// 5 (010): process + command
	// 6 (110): container + command
	// 7 (111): process + container + command
	//
	None      PcapType = 0x0
	Process   PcapType = 0x1
	Container PcapType = 0x2
	Command   PcapType = 0x4
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

	return p, utils.ErrorFuncName(err)
}

func (p *Pcap) write(event *trace.Event, payload []byte) error {

	info := gopacket.CaptureInfo{
		Timestamp:     time.Unix(0, int64(event.Timestamp)),
		CaptureLength: int(len(payload)),
		Length:        int(len(payload)),
	}

	p.writtenPkts++

	err := p.pcapWriter.WritePacket(info, payload)
	if err != nil {
		return utils.ErrorFuncName(err)
	}

	if p.writtenPkts >= flushAtPackets {
		err = p.flush()
		if err != nil {
			logger.Error("Flushing pcap", "error", err)
		}
	}

	return nil
}

func (p *Pcap) flush() error {
	p.writtenPkts = 0
	return p.pcapWriter.Flush()
}

func (p *Pcap) close() error {
	err := p.flush()
	if err != nil {
		logger.Error("Flushing pcap", "error", err)
	}

	return p.pcapFile.Close()
}
