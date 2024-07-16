package config

import (
	"io"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// Config is a struct containing user defined configuration to initialize Tracee
//
// NOTE: In the future, Tracee config will be changed at run time and will require
// proper management.
type Config struct {
	InitialPolicies     []*policy.Policy
	Capture             *CaptureConfig
	Capabilities        *CapabilitiesConfig
	Output              *OutputConfig
	Cache               queue.CacheConfig
	ProcTree            proctree.ProcTreeConfig
	PerfBufferSize      int
	BlobPerfBufferSize  int
	PipelineChannelSize int
	MaxPidsCache        int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath          string
	BPFObjBytes         []byte
	KernelConfig        *environment.KernelConfig
	OSInfo              *environment.OSInfo
	Sockets             runtime.Sockets
	NoContainersEnrich  bool
	EngineConfig        engine.Config
	MetricsEnabled      bool
	DNSCacheConfig      dnscache.Config
}

// Validate does static validation of the configuration
func (c Config) Validate() error {
	// Buffer sizes
	if (c.PerfBufferSize & (c.PerfBufferSize - 1)) != 0 {
		return errfmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (c.BlobPerfBufferSize & (c.BlobPerfBufferSize - 1)) != 0 {
		return errfmt.Errorf("invalid perf buffer size - must be a power of 2")
	}

	// Capture
	if len(c.Capture.FileWrite.PathFilter) > 3 {
		return errfmt.Errorf("too many file-write path filters given")
	}
	for _, filter := range c.Capture.FileWrite.PathFilter {
		if len(filter) > 50 {
			return errfmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}
	if len(c.Capture.FileRead.PathFilter) > 3 {
		return errfmt.Errorf("too many file-read path filters given")
	}
	for _, filter := range c.Capture.FileWrite.PathFilter {
		if len(filter) > 50 {
			return errfmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}

	// BPF
	if c.BPFObjBytes == nil {
		return errfmt.Errorf("nil bpf object in memory")
	}

	return nil
}

//
// Capture
//

type CaptureConfig struct {
	OutputPath string
	FileWrite  FileCaptureConfig
	FileRead   FileCaptureConfig
	Module     bool
	Exec       bool
	Mem        bool
	Bpf        bool
	Net        PcapsConfig
}

type FileCaptureConfig struct {
	Capture    bool
	PathFilter []string
	TypeFilter FileCaptureType
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
	CaptureELFFiles
)

// Filters for FDs flags
const (
	CaptureStdinFiles FileCaptureType = 1 << (iota + 16)
	CaptureStdoutFiles
	CaptureStderrFiles
)

type PcapsConfig struct {
	CaptureSingle    bool
	CaptureProcess   bool
	CaptureContainer bool
	CaptureCommand   bool
	CaptureFiltered  bool
	CaptureLength    uint32
}

//
// Capabilities
//

type CapabilitiesConfig struct {
	BypassCaps bool
	AddCaps    []string
	DropCaps   []string
}

//
// Output
//

type CalcHashesOption int

const (
	CalcHashesNone CalcHashesOption = iota
	CalcHashesInode
	CalcHashesDevInode
	CalcHashesDigestInode
)

func (c CalcHashesOption) String() string {
	switch c {
	case CalcHashesNone:
		return "none"
	case CalcHashesInode:
		return "pathname"
	case CalcHashesDevInode:
		return "dev-inode"
	case CalcHashesDigestInode:
		return "digest-inode"
	default:
		return "unknown"
	}
}

type OutputConfig struct {
	StackAddresses bool
	ExecEnv        bool
	RelativeTime   bool
	CalcHashes     CalcHashesOption

	ParseArguments    bool
	ParseArgumentsFDs bool
	EventsSorting     bool
}

type ContainerMode int

const (
	ContainerModeDisabled ContainerMode = iota
	ContainerModeEnabled
	ContainerModeEnriched
)

type PrinterConfig struct {
	Kind          string
	OutPath       string
	OutFile       io.WriteCloser
	ContainerMode ContainerMode
	RelativeTS    bool
}
