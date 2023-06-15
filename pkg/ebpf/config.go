package ebpf

import (
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/trace"
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	Policies           *policy.Policies
	Capture            *CaptureConfig
	Capabilities       *CapabilitiesConfig
	Output             *OutputConfig
	Cache              queue.CacheConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	maxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath         string
	BPFObjBytes        []byte
	KernelConfig       *helpers.KernelConfig
	ChanEvents         chan trace.Event
	OSInfo             *helpers.OSInfo
	Sockets            runtime.Sockets
	ContainersEnrich   bool
	EngineConfig       engine.Config
	MetricsEnabled     bool
}

type CaptureConfig struct {
	OutputPath string
	FileWrite  FileCaptureConfig
	FileRead   FileCaptureConfig
	Module     bool
	Exec       bool
	Mem        bool
	Bpf        bool
	Net        pcaps.Config
}

type CapabilitiesConfig struct {
	BypassCaps bool
	AddCaps    []string
	DropCaps   []string
}

type OutputConfig struct {
	StackAddresses bool
	ExecEnv        bool
	RelativeTime   bool
	ExecHash       bool

	ParseArguments    bool
	ParseArgumentsFDs bool
	EventsSorting     bool
}

type FileCaptureConfig struct {
	Capture    bool
	PathFilter []string
	TypeFilter FileCaptureType
}

// InitValues determines if to initialize values that might be needed by eBPF programs
type InitValues struct {
	kallsyms bool
}

// FileCaptureType represents file type capture configuration flags
// Values should match the filter values in the eBPF file (
// CaptureRegularFiles -> FILTER_NORMAL_FILES)
type FileCaptureType uint

// Filters for file types flags
const (
	CaptureRegularFiles FileCaptureType = 1 << iota
	CapturePipeFiles
	CaptureSocketFiles
)

// Filters for FDs flags
const (
	CaptureStdinFiles FileCaptureType = 1 << (iota + 16)
	CaptureStdoutFiles
	CaptureStderrFiles
)

// Validate does static validation of the configuration
func (tc Config) Validate() error {
	tc.Policies.ReadLock()
	for p := range tc.Policies.Map() {
		if p == nil {
			tc.Policies.ReadUnlock()
			return errfmt.Errorf("policy is nil")
		}
		if p.EventsToTrace == nil {
			tc.Policies.ReadUnlock()
			return errfmt.Errorf("policy [%d] has no events to trace", p.ID)
		}

		for e := range p.EventsToTrace {
			_, exists := events.Definitions.GetSafe(e)
			if !exists {
				tc.Policies.ReadUnlock()
				return errfmt.Errorf("invalid event [%d] to trace in policy [%d]", e, p.ID)
			}
		}
	}
	tc.Policies.ReadUnlock()

	if (tc.PerfBufferSize & (tc.PerfBufferSize - 1)) != 0 {
		return errfmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (tc.BlobPerfBufferSize & (tc.BlobPerfBufferSize - 1)) != 0 {
		return errfmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if len(tc.Capture.FileWrite.PathFilter) > 3 {
		return errfmt.Errorf("too many file-write path filters given")
	}
	for _, filter := range tc.Capture.FileWrite.PathFilter {
		if len(filter) > 50 {
			return errfmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}
	if len(tc.Capture.FileRead.PathFilter) > 3 {
		return errfmt.Errorf("too many file-read path filters given")
	}
	for _, filter := range tc.Capture.FileWrite.PathFilter {
		if len(filter) > 50 {
			return errfmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}

	if tc.BPFObjBytes == nil {
		return errfmt.Errorf("nil bpf object in memory")
	}

	if tc.ChanEvents == nil {
		return errfmt.Errorf("nil events channel")
	}

	return nil
}
