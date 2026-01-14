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

// Error variables and helper functions
var (
	invalidKernelEventsBufferSizeError = errfmt.Errorf("invalid kernel events buffer size - must be a power of 2")

	invalidKernelArtifactsBufferSizeError = errfmt.Errorf("invalid kernel artifacts buffer size - must be a power of 2")

	invalidArtifactsFileWriteTooManyPathFiltersError = errfmt.Errorf("invalid artifacts file-write too many path filters")

	invalidArtifactsFileReadTooManyPathFiltersError = errfmt.Errorf("invalid artifacts file-read too many path filters")

	nilBPFObjectError = errfmt.Errorf("nil bpf object in memory")
)

func invalidPathFilterError(filter string) error {
	return errfmt.Errorf("invalid artifacts path filter: %s, the length is limited to 50 characters", filter)
}

func invalidStreamConfigError(streamName string) error {
	return errfmt.Errorf("invalid stream config each stream must have at least 1 destination %s", streamName)
}

// Config is a struct containing user defined configuration to initialize Tracee
//
// NOTE: In the future, Tracee config will be changed at run time and will require
// proper management.
type Config struct {
	InitialPolicies   []interface{} // due to circular dependency, policy.Policy cannot be used here
	Artifacts         *ArtifactsConfig
	Capabilities      *CapabilitiesConfig
	Output            *OutputConfig
	ProcessStore      process.ProcTreeConfig
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
		return invalidKernelEventsBufferSizeError
	}
	if (c.Buffers.Kernel.Artifacts & (c.Buffers.Kernel.Artifacts - 1)) != 0 {
		return invalidKernelArtifactsBufferSizeError
	}

	// Artifacts
	if len(c.Artifacts.FileWrite.PathFilter) > 3 {
		return invalidArtifactsFileWriteTooManyPathFiltersError
	}
	for _, filter := range c.Artifacts.FileWrite.PathFilter {
		if len(filter) > 50 {
			return invalidPathFilterError(filter)
		}
	}
	if len(c.Artifacts.FileRead.PathFilter) > 3 {
		return invalidArtifactsFileReadTooManyPathFiltersError
	}
	for _, filter := range c.Artifacts.FileRead.PathFilter {
		if len(filter) > 50 {
			return invalidPathFilterError(filter)
		}
	}

	// Streams
	for _, s := range c.Output.Streams {
		if len(s.Destinations) == 0 {
			return invalidStreamConfigError(s.Name)
		}
	}

	// BPF
	if c.BPFObjBytes == nil {
		return nilBPFObjectError
	}

	return nil
}

//
// Artifacts
//

type ArtifactsConfig struct {
	OutputPath string
	FileWrite  FileArtifactsConfig
	FileRead   FileArtifactsConfig
	Module     bool
	Exec       bool
	Mem        bool
	Bpf        bool
	Net        PcapsConfig
}

type FileArtifactsConfig struct {
	Capture    bool
	PathFilter []string
	TypeFilter FileArtifactsType
}

// FileArtifactsType represents file type artifacts configuration flags
// Values should match the filter values in the eBPF file (
// ArtifactsRegularFiles -> FILTER_NORMAL_FILES)
type FileArtifactsType uint

// Filters for file types flags
const (
	ArtifactsRegularFiles FileArtifactsType = 1 << iota
	ArtifactsPipeFiles
	ArtifactsSocketFiles
	ArtifactsELFFiles
)

// Filters for FDs flags
const (
	ArtifactsStdinFiles FileArtifactsType = 1 << (iota + 16)
	ArtifactsStdoutFiles
	ArtifactsStderrFiles
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
