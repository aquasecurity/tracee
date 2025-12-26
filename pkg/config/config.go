package config

import (
	"io"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
)

// Config is a struct containing user defined configuration to initialize Tracee
//
// NOTE: In the future, Tracee config will be changed at run time and will require
// proper management.
type Config struct {
	InitialPolicies   []interface{} // due to circular dependency, policy.Policy cannot be used here
	Capture           *CaptureConfig
	Capabilities      *CapabilitiesConfig
	Output            *OutputConfig
	ProcTree          process.ProcTreeConfig
	Buffers           BuffersConfig
	MaxPidsCache      int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath        string
	BPFObjBytes       []byte
	BPFObjPath        string // path to the BPF object binary for uprobe attachment (defaults to /proc/self/exe)
	KernelConfig      *environment.KernelConfig
	OSInfo            *environment.OSInfo
	Sockets           runtime.Sockets
	EnrichmentEnabled bool
	CgroupFSPath      string
	CgroupFSForce     bool
	EngineConfig      engine.Config
	DNSStore          dns.Config
	MetricsEnabled    bool
	HealthzEnabled    bool
	DetectorConfig    DetectorConfig
}

// Validate does static validation of the configuration
func (c Config) Validate() error {
	// Buffer sizes
	if (c.Buffers.Kernel.Events & (c.Buffers.Kernel.Events - 1)) != 0 {
		return errfmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (c.Buffers.Kernel.Artifacts & (c.Buffers.Kernel.Artifacts - 1)) != 0 {
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

	// Streams
	for _, s := range c.Output.Streams {
		if len(s.Destinations) == 0 {
			return errfmt.Errorf("each stream must have at least 1 destination %s", s.Name)
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

type OutputConfig struct {
	StackAddresses bool
	ExecEnv        bool
	CalcHashes     digest.CalcHashesOption

	ParseArguments    bool
	ParseArgumentsFDs bool
	EventsSorting     bool

	Streams []Stream
}

type ContainerMode int

const (
	ContainerModeDisabled ContainerMode = iota
	ContainerModeEnabled
	ContainerModeEnriched
)

type Destination struct {
	Name          string
	Type          string
	Format        string
	Path          string
	Url           string
	File          io.WriteCloser
	ContainerMode ContainerMode
}

type StreamBufferMode string

const (
	StreamBufferBlock StreamBufferMode = "block"
	StreamBufferDrop  StreamBufferMode = "drop"
)

type StreamFilters struct {
	Policies []string
	Events   []string
}

type StreamBuffer struct {
	Size int
	Mode StreamBufferMode
}

type Stream struct {
	Name         string
	Destinations []Destination
	Filters      StreamFilters
	Buffer       StreamBuffer
}

// DetectorConfig manages detector lifecycle and YAML detector discovery
type DetectorConfig struct {
	Detectors      []detection.EventDetector // All detectors (built-in + extensions)
	YAMLSearchDirs []string                  // Directories to search for YAML detectors
}

//
// Buffers
//

// BuffersConfig is a struct containing the buffers sizes
type BuffersConfig struct {
	Kernel   KernelBuffersConfig `mapstructure:"kernel"`
	Pipeline int                 `mapstructure:"pipeline"`
}

// KernelBuffersConfig holds kernel buffer sizes
type KernelBuffersConfig struct {
	Events       int `mapstructure:"events"`
	Artifacts    int `mapstructure:"artifacts"`
	ControlPlane int `mapstructure:"control-plane"`
}
