package flags

import (
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	BuffersFlag          = "buffers"
	EventsSizeFlag       = "kernel-events"
	BlobSizeFlag         = "kernel-blob"
	ControlPlaneSizeFlag = "control-plane-events"
	PipelineSizeFlag     = "pipeline"
)

func buffersFlagHelp() string {
	return `Configure the buffers sizes.

Flags:
  --buffers kernel-events=<size>	Size, in pages, of the internal perf ring buffer used to submit events from the kernel
  --buffers kernel-blob=<size>	Size, in pages, of the internal perf ring buffer used to send blobs from the kernel
  --buffers control-plane-events=<size>	Size, in pages, of the internal perf ring buffer used to submit events from the control plane
  --buffers pipeline=<size>	Size, in event objects, of each pipeline stage's output channel
`
}

// Buffers is a struct containing the buffers sizes
type Buffers struct {
	EventsSize       int
	BlobSize         int
	ControlPlaneSize int
	PipelineSize     int
}

// PrepareBuffers prepares the buffers based on the flags
// flags is a slice of strings in the format "flag=value", e.g. "kernel-events=1024"
// returns a Buffers struct and an error if the flags are invalid
func PrepareBuffers(flags []string) (Buffers, error) {
	// default values are 4 MB for the kernel events buffer,

	buffers := Buffers{
		EventsSize:       GetDefaultPerfBufferSize(),
		BlobSize:         GetDefaultPerfBufferSize(),
		ControlPlaneSize: GetDefaultPerfBufferSize(),
		PipelineSize:     10_000,
	}

	for _, flag := range flags {
		values := strings.Split(flag, "=")

		if len(values) != 2 || values[0] == "" || values[1] == "" {
			return Buffers{}, errfmt.Errorf("invalid buffer flag: %s, use 'trace man buffers' for more info", flag)
		}

		size, err := strconv.Atoi(values[1])
		if err != nil {
			return Buffers{}, errfmt.Errorf("invalid buffer flag: %s value must be a positive integer, use 'trace man buffers' for more info", values[0])
		}

		if size <= 0 {
			return Buffers{}, errfmt.Errorf("invalid buffer flag: %s value can't be negative or zero, use 'trace man buffers' for more info", values[0])
		}

		switch values[0] {
		case EventsSizeFlag:
			buffers.EventsSize = size
		case BlobSizeFlag:
			buffers.BlobSize = size
		case PipelineSizeFlag:
			buffers.PipelineSize = size
		case ControlPlaneSizeFlag:
			buffers.ControlPlaneSize = size
		default:
			return Buffers{}, errfmt.Errorf("invalid buffer flag: %s, use 'trace man buffers' for more info", values[0])
		}
	}

	return buffers, nil
}

func GetDefaultPerfBufferSize() int {
	return (4096 * 1024) / os.Getpagesize()
}
