package pcaps

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

var outputDirectory *os.File
var fake pcapgo.NgInterface

const (
	pcapDir       string = "pcap/"
	pcapSingleDir string = pcapDir
	pcapProcDir   string = pcapDir + "processes/"
	pcapContDir   string = pcapDir + "containers/"
	pcapCommDir   string = pcapDir + "commands/"
)

const (
	pcapsToCache   = 100 // number of pcaps to keep cached in LRU cache
	flushAtPackets = 1   // flush pcap file after X number of packets
)

// TODO: flush per interval as well (so we can grow flushAtPackets higher)

const AF_INET = 2
const AF_INET6 = 10

//
// Functions
//

func initializeGlobalVars(output *os.File) {
	outputDirectory = output // where to save pcap files

	// fake interface to be added to each pcap file (needed)
	fake = pcapgo.NgInterface{ // https://www.tcpdump.org/linktypes.html
		Name:        "tracee",
		Comment:     "trace fake interface",
		Description: "non-existing interface",
		LinkType:    layers.LinkTypeNull, // layer2 is 4 bytes (or 32bit)
		SnapLength:  uint32(math.MaxUint32),
	}
}

// getItemIndexFromEvent returns correct trace.Event variable according to
// given PcapType
func getItemIndexFromEvent(event *trace.Event, itemType PcapType) interface{} {
	switch itemType {
	case Single:
		return itemType.String()
	case Process:
		return event.HostThreadID
	case Container:
		return event.Container.ID
	case Command:
		// index by using container_id and comm (to avoid having all
		// captured packets in command/host/XXX, as it would occur if
		// indexing by container_id only).
		ret := fmt.Sprintf("%s:%s", event.Container.ID, event.ProcessName)
		return ret
	}

	return new(interface{})
}

// getPcapFileName returns a string used to create a pcap file under the
// capture output directory.
func getPcapFileName(event *trace.Event, pcapType PcapType) (string, error) {
	var err error

	contID := getContainerID(event.Container.ID)

	// create needed dirs
	err = mkdirForPcapType(outputDirectory, contID, pcapType)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	// return filename in format according to pcap type
	return getFileStringFormat(event, contID, pcapType), nil
}

// getContainerID returns the container string to be used in pcap files or dirs
func getContainerID(contID string) string {
	if contID == "" {
		return "host"
	}
	if len(contID) > 11 {
		contID = contID[0:11]
	}

	return contID
}

// getFileStringFormat creates the string that will hold the pcap filename
func getFileStringFormat(e *trace.Event, c string, t PcapType) string {
	var format string

	switch t {
	case Single:
		format = fmt.Sprintf(
			"%s%s.pcap", // single.pcap
			pcapSingleDir,
			strings.ToLower(t.String()),
		)
	case Process:
		format = fmt.Sprintf(
			pcapProcDir+"%v/%v_%v_%v.pcap",
			c,
			e.ProcessName,
			e.HostThreadID,
			e.ThreadStartTime,
		)
	case Container:
		format = fmt.Sprintf(
			pcapContDir+"%v.pcap",
			c,
		)
	case Command:
		format = fmt.Sprintf(
			pcapCommDir+"%v/%v.pcap",
			c,
			e.ProcessName,
		)
	}

	return format
}

// mkdirForPcapType creates the dir that will hold the pcap file(s)
func mkdirForPcapType(o *os.File, c string, t PcapType) error {
	var e error

	s := "pcap"

	e = utils.MkdirAtExist(o, s, os.ModePerm)
	if e != nil {
		return errfmt.WrapError(e)
	}

	switch t {
	case Single:
		e = utils.MkdirAtExist(o, pcapSingleDir, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
	case Process:
		e = utils.MkdirAtExist(o, pcapProcDir, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
		e = utils.MkdirAtExist(o, pcapProcDir+c, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
	case Container:
		e = utils.MkdirAtExist(o, pcapContDir, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
	case Command:
		e = utils.MkdirAtExist(o, pcapCommDir, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
		e = utils.MkdirAtExist(o, pcapCommDir+c, os.ModePerm)
		if e != nil {
			return errfmt.WrapError(e)
		}
	}

	return nil
}

// getPcapFileAndWriter returns a file descriptor and and its associated pcap
// writer depending on the type "t" given (a Pcap interface implementation).
func getPcapFileAndWriter(event *trace.Event, t PcapType) (
	*os.File,
	*pcapgo.NgWriter,
	error,
) {
	pcapFilePath, err := getPcapFileName(event, t)
	if err != nil {
		return nil, nil, errfmt.WrapError(err)
	}
	file, err := utils.OpenAt(
		outputDirectory,
		pcapFilePath,
		os.O_APPEND|os.O_WRONLY|os.O_CREATE,
		0644,
	)
	if err != nil {
		return nil, nil, errfmt.WrapError(err)
	}

	logger.Debugw("pcap file (re)opened", "filename", pcapFilePath)

	writer, err := pcapgo.NewNgWriterInterface(
		file,
		fake,
		pcapgo.DefaultNgWriterOptions,
	)
	if err != nil {
		return nil, nil, errfmt.WrapError(err)
	}
	err = writer.Flush()
	if err != nil {
		return nil, nil, errfmt.WrapError(err)
	}

	return file, writer, nil
}

// configToPcapType converts a simple bool like config struct to internal config
func configToPcapType(simple Config) PcapType {
	var config PcapType

	if simple.CaptureSingle {
		config |= Single
	}
	if simple.CaptureProcess {
		config |= Process
	}
	if simple.CaptureContainer {
		config |= Container
	}
	if simple.CaptureCommand {
		config |= Command
	}

	return config
}

// PcapsEnabled checks if the simple config has any bool value set
func PcapsEnabled(simple Config) bool {
	config := configToPcapType(simple)
	return config != None
}

func GetPcapOptions(c Config) PcapOption {
	var options PcapOption

	if c.CaptureFiltered {
		options |= Filtered
	}

	return options
}
