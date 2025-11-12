package config

import (
	"io"

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
	InitialPolicies            []interface{} // due to circular dependency, policy.Policy cannot be used here
	Capture                    *CaptureConfig
	Capabilities               *CapabilitiesConfig
	Output                     *OutputConfig
	ProcTree                   process.ProcTreeConfig
	PerfBufferSize             int
	BlobPerfBufferSize         int
	PipelineChannelSize        int
	ControlPlanePerfBufferSize int
	MaxPidsCache               int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath                 string
	BPFObjBytes                []byte
	BPFObjPath                 string // path to the BPF object binary for uprobe attachment (defaults to /proc/self/exe)
	KernelConfig               *environment.KernelConfig
	OSInfo                     *environment.OSInfo
	Sockets                    runtime.Sockets
	NoContainersEnrich         bool
	CgroupFSPath               string
	CgroupFSForce              bool
	EngineConfig               engine.Config
	MetricsEnabled             bool
	DNSCacheConfig             dns.Config
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

// --capture file-write.enabled=<true/false> \
// --capture file-write.filters= (multiple allowed)
// --capture file-read.enabled=<true/false>
// --capture file-read.filters= (multiple allowed)
// --capture executable.enabled=<true/false>
// --capture kernel-modules.enabled=<true/false>
// --capture bpf-programs.enabled=<true/false>
// --capture memory-regions.enabled=<true/false>
// --capture network.enabled=<true/false>
// --capture network.pcap=<split_mode>
// --capture network.pcap-options=
// --capture network.pcap-snaplen=
// --capture dir.path= (default: /tmp/tracee)
// --capture dir.clear=<true/false> (default: false)

type NCaptureConfig struct {
	Executable    bool
	KernelModules bool
	BpfPrograms   bool
	MemoryRegions bool
	FileWrite     FileWriteCaptureConfig
	FileRead      FileReadCaptureConfig
	Network       NetworkCaptureConfig
	Output        OutputCaptureConfig
}

type FileWriteCaptureConfig struct {
	Enabled    bool
	PathFilter []string
}

type FileReadCaptureConfig struct {
	Enabled    bool
	PathFilter []string
}

type NetworkCaptureConfig struct {
	Enabled   bool
	Single    bool
	Length    uint32
	Filtered  bool
	Process   bool
	Container bool
	Command   bool
}

type OutputCaptureConfig struct {
	Path  string
	Clear bool
}

// Legacy below

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
}
