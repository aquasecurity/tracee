package ebpf

import (
	gocontext "context"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/ebpf/controlplane"
	"github.com/aquasecurity/tracee/pkg/ebpf/initialization"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/events/sorting"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/filehash"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/streams"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	pkgName          = "tracee"
	maxMemDumpLength = 127
)

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config    config.Config
	bootTime  uint64
	startTime uint64
	running   atomic.Bool
	done      chan struct{} // signal to safely stop end-stage processing
	OutDir    *os.File      // use utils.XXX functions to create or write to this file
	stats     *metrics.Stats
	sigEngine *engine.Engine
	// Events
	eventsSorter     *sorting.EventsChronologicalSorter
	eventsPool       *sync.Pool
	eventsFieldTypes map[events.ID][]bufferdecoder.ArgType
	eventProcessor   map[events.ID][]func(evt *trace.Event) error
	eventDerivations derive.Table
	// Artifacts
	fileHashes     *filehash.Cache
	capturedFiles  map[string]int64
	writtenFiles   map[string]string
	netCapturePcap *pcaps.Pcaps
	// Internal Data
	readFiles     map[string]string
	pidsInMntns   bucketscache.BucketsCache // first n PIDs in each mountns
	kernelSymbols *environment.KernelSymbolTable
	// eBPF
	bpfModule     *bpf.Module
	defaultProbes *probes.ProbeGroup
	extraProbes   map[string]*probes.ProbeGroup
	// BPF Maps
	StackAddressesMap *bpf.BPFMap
	FDArgPathMap      *bpf.BPFMap
	// Perf Buffers
	eventsPerfMap  *bpf.PerfBuffer // perf buffer for events
	fileWrPerfMap  *bpf.PerfBuffer // perf buffer for file writes
	netCapPerfMap  *bpf.PerfBuffer // perf buffer for network captures
	bpfLogsPerfMap *bpf.PerfBuffer // perf buffer for bpf logs
	// Events Channels
	eventsChannel       chan []byte // channel for events
	fileCapturesChannel chan []byte // channel for file writes
	netCapChannel       chan []byte // channel for network captures
	bpfLogsChannel      chan []byte // channel for bpf logs
	// Lost Events Channels
	lostEvChannel       chan uint64 // channel for lost events
	lostCapturesChannel chan uint64 // channel for lost file writes
	lostNetCapChannel   chan uint64 // channel for lost network captures
	lostBPFLogChannel   chan uint64 // channel for lost bpf logs
	// Containers
	cgroups           *cgroup.Cgroups
	containers        *containers.Containers
	contPathResolver  *containers.ContainerPathResolver
	contSymbolsLoader *sharedobjs.ContainersSymbolsLoader
	// Control Plane
	controlPlane *controlplane.Controller
	// Process Tree
	processTree *proctree.ProcessTree
	// DNS Cache
	dnsCache *dnscache.DNSCache
	// Specific Events Needs
	triggerContexts trigger.Context
	readyCallback   func(gocontext.Context)
	// Streams
	streamsManager *streams.StreamsManager
	// policyManager manages policy state
	policyManager *policy.Manager
	// The dependencies of events used by Tracee
	eventsDependencies *dependencies.Manager
	// Ksymbols needed to be kept alive in table.
	// This does not mean they are required for tracee to function.
	// TODO: remove this in favor of dependency manager nodes
	requiredKsyms []string
}

func (t *Tracee) Stats() *metrics.Stats {
	return t.stats
}

func (t *Tracee) Engine() *engine.Engine {
	return t.sigEngine
}

// New creates a new Tracee instance based on a given valid Config. It is expected that it won't
// cause external system side effects (reads, writes, etc).
func New(cfg config.Config) (*Tracee, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, errfmt.Errorf("validation error: %v", err)
	}

	// Initialize capabilities rings soon

	useBaseEbpf := func(cfg config.Config) bool {
		return cfg.Output.StackAddresses
	}

	err = capabilities.Initialize(
		capabilities.Config{
			Bypass:   cfg.Capabilities.BypassCaps,
			BaseEbpf: useBaseEbpf(cfg),
		},
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	caps := capabilities.GetInstance()

	// Initialize Dependencies Manager

	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.Dependencies {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// Initialize Policy Manager

	initialPolicies := make([]*policy.Policy, 0, len(cfg.InitialPolicies))
	for _, v := range cfg.InitialPolicies {
		p, ok := v.(*policy.Policy)
		if !ok {
			return nil, errfmt.Errorf("invalid policy type: %T", v)
		}
		initialPolicies = append(initialPolicies, p)
	}

	// NOTE: This deep copy is a *reminder* that the inner slices are not shared
	// between the original and the injected config.
	// TODO: This logic should be removed when config changes in runtime is a thing.
	getNewCaptureConfig := func() config.CaptureConfig {
		fileReadPathFilter := make([]string, 0, len(cfg.Capture.FileRead.PathFilter))
		copy(fileReadPathFilter, cfg.Capture.FileRead.PathFilter)
		fileRead := config.FileCaptureConfig{
			Capture:    cfg.Capture.FileRead.Capture,
			PathFilter: fileReadPathFilter,
			TypeFilter: cfg.Capture.FileRead.TypeFilter,
		}

		fileWritePathFilter := make([]string, 0, len(cfg.Capture.FileWrite.PathFilter))
		copy(fileWritePathFilter, cfg.Capture.FileWrite.PathFilter)
		fileWrite := config.FileCaptureConfig{
			Capture:    cfg.Capture.FileWrite.Capture,
			PathFilter: fileWritePathFilter,
			TypeFilter: cfg.Capture.FileWrite.TypeFilter,
		}

		return config.CaptureConfig{
			FileRead:  fileRead,
			FileWrite: fileWrite,
			Module:    cfg.Capture.Module,
			Exec:      cfg.Capture.Exec,
			Mem:       cfg.Capture.Mem,
			Bpf:       cfg.Capture.Bpf,
			Net:       cfg.Capture.Net,
		}
	}

	pmCfg := policy.ManagerConfig{
		DNSCacheConfig: cfg.DNSCacheConfig,
		ProcTreeConfig: cfg.ProcTree,
		CaptureConfig:  getNewCaptureConfig(),
	}
	pm, err := policy.NewManager(pmCfg, depsManager, initialPolicies...)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// Create Tracee

	t := &Tracee{
		config:             cfg,
		done:               make(chan struct{}),
		stats:              metrics.NewStats(),
		writtenFiles:       make(map[string]string),
		readFiles:          make(map[string]string),
		capturedFiles:      make(map[string]int64),
		streamsManager:     streams.NewStreamsManager(),
		policyManager:      pm,
		eventsDependencies: depsManager,
		requiredKsyms:      []string{},
		extraProbes:        make(map[string]*probes.ProbeGroup),
	}

	// clear initial policies to avoid wrong references
	initialPolicies = nil
	t.config.InitialPolicies = nil

	// Add/Drop capabilities to/from the Base ring (always effective)

	capsToAdd, err := capabilities.ReqByString(t.config.Capabilities.AddCaps...)
	if err != nil {
		return t, errfmt.WrapError(err)
	}
	err = caps.BaseRingAdd(capsToAdd...)
	if err != nil {
		return t, errfmt.WrapError(err)
	}

	capsToDrop, err := capabilities.ReqByString(t.config.Capabilities.DropCaps...)
	if err != nil {
		return t, errfmt.WrapError(err)
	}
	err = caps.BaseRingRemove(capsToDrop...)
	if err != nil {
		return t, errfmt.WrapError(err)
	}

	// Register default event processors

	t.registerEventProcessors()

	// Start event triggering logic context

	t.triggerContexts = trigger.NewContext()

	return t, nil
}

// Init initialize tracee instance and it's various subsystems, potentially
// performing external system operations to initialize them.
// NOTE: any initialization logic, especially one that causes side effects
// should go here and not New().
func (t *Tracee) Init(ctx gocontext.Context) error {
	var err error

	// Initialize buckets cache

	var mntNSProcs map[int]int

	if t.config.MaxPidsCache == 0 {
		t.config.MaxPidsCache = 5 // TODO: configure this ? never set, default = 5
	}

	t.pidsInMntns.Init(t.config.MaxPidsCache)

	err = capabilities.GetInstance().Specific(
		func() error {
			mntNSProcs, err = proc.GetMountNSFirstProcesses()
			return err
		},
		cap.DAC_OVERRIDE,
		cap.SYS_PTRACE,
	)
	if err == nil {
		for mountNS, pid := range mntNSProcs {
			t.pidsInMntns.AddBucketItem(uint32(mountNS), uint32(pid))
		}
	} else {
		logger.Debugw("Initializing buckets cache", "error", errfmt.WrapError(err))
	}

	// Initialize cgroups filesystems

	t.cgroups, err = cgroup.NewCgroups()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize containers enrichment logic

	t.containers, err = containers.New(
		t.config.NoContainersEnrich,
		t.cgroups,
		t.config.Sockets,
		"containers_map",
	)
	if err != nil {
		return errfmt.Errorf("error initializing containers: %v", err)
	}
	if err := t.containers.Populate(); err != nil {
		return errfmt.Errorf("error populating containers: %v", err)
	}

	// Initialize DNS Cache

	if t.config.DNSCacheConfig.Enable {
		t.dnsCache, err = dnscache.New(t.config.DNSCacheConfig)
		if err != nil {
			return errfmt.Errorf("error initializing dns cache: %v", err)
		}
	}

	// Initialize containers related logic

	t.contPathResolver = containers.InitContainerPathResolver(&t.pidsInMntns)
	t.contSymbolsLoader = sharedobjs.InitContainersSymbolsLoader(t.contPathResolver, 1024)

	// Initialize eBPF probes

	err = capabilities.GetInstance().EBPF(
		func() error {
			return t.initBPFProbes()
		},
	)
	if err != nil {
		t.Close()
		return errfmt.WrapError(err)
	}

	// Init kernel symbols map

	err = t.initKsymTableRequiredSyms()
	if err != nil {
		return err
	}

	err = capabilities.GetInstance().Specific(
		func() error {
			t.kernelSymbols, err = environment.NewKernelSymbolTable(
				environment.WithRequiredSymbols(t.requiredKsyms),
			)
			// Cleanup memory in list
			t.requiredKsyms = []string{}
			return err
		},
		cap.SYSLOG,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	t.validateKallsymsDependencies() // disable events w/ missing ksyms dependencies

	// Initialize time

	// Checking the kernel symbol needs to happen after obtaining the capability;
	// otherwise, we get a warning.
	usedClockID := traceetime.CLOCK_BOOTTIME
	err = capabilities.GetInstance().EBPF(
		func() error {
			// Since this code is running with sufficient capabilities, we can safely trust the result of `BPFHelperIsSupported`.
			// If the helper is reported as supported (`supported == true`), it is assumed to be reliable for use.
			// If `supported == false`, it indicates that the helper for getting BOOTTIME is not available.
			// The `innerErr` provides information about errors that occurred during the check, regardless of whether `supported`
			// is true or false.
			// For a full explanation of the caveats and behavior, refer to:
			// https://github.com/aquasecurity/libbpfgo/blob/eb576c71ece75930a693b8b0687c5d052a5dbd56/libbpfgo.go#L99-L119
			supported, innerErr := bpf.BPFHelperIsSupported(bpf.BPFProgTypeKprobe, bpf.BPFFuncKtimeGetBootNs)

			// Use CLOCK_MONOTONIC only when the helper is explicitly unsupported
			if !supported {
				usedClockID = traceetime.CLOCK_MONOTONIC
			}

			if innerErr != nil {
				logger.Debugw("Detect clock timing", "warn", innerErr)
			}

			return nil
		})
	if err != nil {
		return errfmt.WrapError(err)
	}

	// init time functionalities
	err = traceetime.Init(int32(usedClockID))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// elapsed time in nanoseconds since system start
	t.startTime = uint64(traceetime.GetStartTimeNS())
	// time in nanoseconds when the system was booted
	t.bootTime = uint64(traceetime.GetBootTimeNS())

	// Initialize event derivation logic

	err = t.initDerivationTable()
	if err != nil {
		return errfmt.Errorf("error initializing event derivation map: %v", err)
	}

	// Initialize events field types map

	t.eventsFieldTypes = make(map[events.ID][]bufferdecoder.ArgType)
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id := eventDefinition.GetID()
		fields := eventDefinition.GetFields()
		for _, field := range fields {
			t.eventsFieldTypes[id] = append(t.eventsFieldTypes[id], bufferdecoder.GetFieldType(field.Type))
		}
	}

	// Initialize Process Tree (if enabled)

	if t.config.ProcTree.Source != proctree.SourceNone {
		// As procfs use boot time to calculate process start time, we can use the procfs
		// only if the times we get from the eBPF programs are based on the boot time (instead of monotonic).
		proctreeConfig := t.config.ProcTree
		if usedClockID == traceetime.CLOCK_MONOTONIC {
			proctreeConfig.ProcfsInitialization = false
			proctreeConfig.ProcfsQuerying = false
		}
		t.processTree, err = proctree.NewProcessTree(ctx, proctreeConfig)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize eBPF programs and maps

	err = capabilities.GetInstance().EBPF(
		func() error {
			return t.initBPF()
		},
	)
	if err != nil {
		t.Close()
		return errfmt.WrapError(err)
	}

	// Initialize hashes for files

	t.fileHashes, err = filehash.NewCache(t.config.Output.CalcHashes, t.contPathResolver)
	if err != nil {
		t.Close()
		return errfmt.WrapError(err)
	}

	// Initialize capture directory

	if err := os.MkdirAll(t.config.Capture.OutputPath, 0755); err != nil {
		t.Close()
		return errfmt.Errorf("error creating output path: %v", err)
	}

	t.OutDir, err = utils.OpenExistingDir(t.config.Capture.OutputPath)
	if err != nil {
		t.Close()
		return errfmt.Errorf("error opening out directory: %v", err)
	}

	// Initialize network capture (all needed pcap files)

	t.netCapturePcap, err = pcaps.New(t.config.Capture.Net, t.OutDir)
	if err != nil {
		t.Close()
		return errfmt.Errorf("error initializing network capture: %v", err)
	}

	// Get reference to stack trace addresses map

	stackAddressesMap, err := t.bpfModule.GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return errfmt.Errorf("error getting access to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = stackAddressesMap

	// Get reference to fd arg path map

	fdArgPathMap, err := t.bpfModule.GetMap("fd_arg_path_map")
	if err != nil {
		t.Close()
		return errfmt.Errorf("error getting access to 'fd_arg_path_map' eBPF Map %v", err)
	}
	t.FDArgPathMap = fdArgPathMap

	// Initialize events sorting (pipeline step)

	if t.config.Output.EventsSorting {
		t.eventsSorter, err = sorting.InitEventSorter()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize events pool

	t.eventsPool = &sync.Pool{
		New: func() interface{} {
			return &trace.Event{}
		},
	}

	// Perform extra initializtion steps required by specific events according to their arguments
	err = capabilities.GetInstance().EBPF(
		func() error {
			return t.handleEventParameters()
		},
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// initTailCall initializes a given tailcall.
func (t *Tracee) initTailCall(tailCall events.TailCall) error {
	tailCallMapName := tailCall.GetMapName()
	tailCallProgName := tailCall.GetProgName()
	tailCallIndexes := tailCall.GetIndexes()

	// Pick eBPF map by name.
	bpfMap, err := t.bpfModule.GetMap(tailCallMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}
	// Pick eBPF program by name.
	bpfProg, err := t.bpfModule.GetProgram(tailCallProgName)
	if err != nil {
		return errfmt.Errorf("could not get BPF program %s: %v", tailCallProgName, err)
	}
	// Pick eBPF program file descriptor.
	bpfProgFD := bpfProg.FileDescriptor()
	if bpfProgFD < 0 {
		return errfmt.Errorf("could not get BPF program FD for %s: %v", tailCallProgName, err)
	}

	// Pick all indexes (event, or syscall, IDs) the BPF program should be related to.
	for _, index := range tailCallIndexes {
		// Workaround: Do not map eBPF program to unsupported syscalls (arm64, e.g.)
		if index >= uint32(events.Unsupported) {
			continue
		}
		// Update given eBPF map with the eBPF program file descriptor at given index.
		err := bpfMap.Update(unsafe.Pointer(&index), unsafe.Pointer(&bpfProgFD))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

// initDerivationTable initializes tracee's events.DerivationTable. For each
// event, represented through its ID, we declare to which other events it can be
// derived and the corresponding function to derive into that Event.
func (t *Tracee) initDerivationTable() error {
	shouldSubmit := func(id events.ID) func() bool {
		return func() bool { return t.policyManager.IsEventToSubmit(id) }
	}
	symbolsCollisions := derive.SymbolsCollision(t.contSymbolsLoader, t.policyManager)

	executeFailedGen, err := derive.InitProcessExecuteFailedGenerator()
	if err != nil {
		logger.Errorw("failed to init derive function for ProcessExecuteFiled", "error", err)
		return nil
	}

	t.eventDerivations = derive.Table{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:        shouldSubmit(events.ContainerCreate),
				DeriveFunction: derive.ContainerCreate(t.containers),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:        shouldSubmit(events.ContainerRemove),
				DeriveFunction: derive.ContainerRemove(t.containers),
			},
		},
		events.SyscallTableCheck: {
			events.HookedSyscall: {
				Enabled:        shouldSubmit(events.SyscallTableCheck),
				DeriveFunction: derive.DetectHookedSyscall(t.kernelSymbols),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:        shouldSubmit(events.HookedSeqOps),
				DeriveFunction: derive.HookedSeqOps(t.kernelSymbols),
			},
		},
		events.HiddenKernelModuleSeeker: {
			events.HiddenKernelModule: {
				Enabled:        shouldSubmit(events.HiddenKernelModuleSeeker),
				DeriveFunction: derive.HiddenKernelModule(),
			},
		},
		events.SharedObjectLoaded: {
			events.SymbolsLoaded: {
				Enabled: shouldSubmit(events.SymbolsLoaded),
				DeriveFunction: derive.SymbolsLoaded(
					t.contSymbolsLoader,
					t.policyManager,
				),
			},
			events.SymbolsCollision: {
				Enabled:        shouldSubmit(events.SymbolsCollision),
				DeriveFunction: symbolsCollisions,
			},
		},
		events.SchedProcessExec: {
			events.SymbolsCollision: {
				Enabled:        shouldSubmit(events.SymbolsCollision),
				DeriveFunction: symbolsCollisions,
			},
		},
		events.SecuritySocketConnect: {
			events.NetTCPConnect: {
				Enabled: shouldSubmit(events.NetTCPConnect),
				DeriveFunction: derive.NetTCPConnect(
					t.dnsCache,
				),
			},
		},
		events.ExecuteFinished: {
			events.ProcessExecuteFailed: {
				Enabled:        shouldSubmit(events.ProcessExecuteFailed),
				DeriveFunction: executeFailedGen.ProcessExecuteFailed(),
			},
		},
		events.ProcessExecuteFailedInternal: {
			events.ProcessExecuteFailed: {
				Enabled:        shouldSubmit(events.ProcessExecuteFailed),
				DeriveFunction: executeFailedGen.ProcessExecuteFailed(),
			},
		},
		//
		// Network Packet Derivations
		//
		events.NetPacketIPBase: {
			events.NetPacketIPv4: {
				Enabled:        shouldSubmit(events.NetPacketIPv4),
				DeriveFunction: derive.NetPacketIPv4(),
			},
			events.NetPacketIPv6: {
				Enabled:        shouldSubmit(events.NetPacketIPv6),
				DeriveFunction: derive.NetPacketIPv6(),
			},
		},
		events.NetPacketTCPBase: {
			events.NetPacketTCP: {
				Enabled:        shouldSubmit(events.NetPacketTCP),
				DeriveFunction: derive.NetPacketTCP(),
			},
		},
		events.NetPacketUDPBase: {
			events.NetPacketUDP: {
				Enabled:        shouldSubmit(events.NetPacketUDP),
				DeriveFunction: derive.NetPacketUDP(),
			},
		},
		events.NetPacketICMPBase: {
			events.NetPacketICMP: {
				Enabled:        shouldSubmit(events.NetPacketICMP),
				DeriveFunction: derive.NetPacketICMP(),
			},
		},
		events.NetPacketICMPv6Base: {
			events.NetPacketICMPv6: {
				Enabled:        shouldSubmit(events.NetPacketICMPv6),
				DeriveFunction: derive.NetPacketICMPv6(),
			},
		},
		events.NetPacketDNSBase: {
			events.NetPacketDNS: {
				Enabled:        shouldSubmit(events.NetPacketDNS),
				DeriveFunction: derive.NetPacketDNS(),
			},
			events.NetPacketDNSRequest: {
				Enabled:        shouldSubmit(events.NetPacketDNSRequest),
				DeriveFunction: derive.NetPacketDNSRequest(),
			},
			events.NetPacketDNSResponse: {
				Enabled:        shouldSubmit(events.NetPacketDNSResponse),
				DeriveFunction: derive.NetPacketDNSResponse(),
			},
		},
		events.NetPacketHTTPBase: {
			events.NetPacketHTTP: {
				Enabled:        shouldSubmit(events.NetPacketHTTP),
				DeriveFunction: derive.NetPacketHTTP(),
			},
			events.NetPacketHTTPRequest: {
				Enabled:        shouldSubmit(events.NetPacketHTTPRequest),
				DeriveFunction: derive.NetPacketHTTPRequest(),
			},
			events.NetPacketHTTPResponse: {
				Enabled:        shouldSubmit(events.NetPacketHTTPResponse),
				DeriveFunction: derive.NetPacketHTTPResponse(),
			},
		},
		//
		// Network Flow Derivations
		//
		events.NetPacketFlow: {
			events.NetFlowTCPBegin: {
				Enabled: shouldSubmit(events.NetFlowTCPBegin),
				DeriveFunction: derive.NetFlowTCPBegin(
					t.dnsCache,
				),
			},
			events.NetFlowTCPEnd: {
				Enabled: shouldSubmit(events.NetFlowTCPEnd),
				DeriveFunction: derive.NetFlowTCPEnd(
					t.dnsCache,
				),
			},
		},
	}

	return nil
}

// options config should match defined values in ebpf code
const (
	optExecEnv uint32 = 1 << iota
	optCaptureFilesWrite
	optExtractDynCode
	optStackAddresses
	optCaptureModules
	optCgroupV1
	optTranslateFDFilePath
	optCaptureBpf
	optCaptureFileRead
	optForkProcTree
)

func (t *Tracee) getOptionsConfig() uint32 {
	var cOptVal uint32

	if t.config.Output.ExecEnv {
		cOptVal = cOptVal | optExecEnv
	}
	if t.config.Output.StackAddresses {
		cOptVal = cOptVal | optStackAddresses
	}
	if t.config.Capture.FileWrite.Capture {
		cOptVal = cOptVal | optCaptureFilesWrite
	}
	if t.config.Capture.FileRead.Capture {
		cOptVal = cOptVal | optCaptureFileRead
	}
	if t.config.Capture.Module {
		cOptVal = cOptVal | optCaptureModules
	}
	if t.config.Capture.Bpf {
		cOptVal = cOptVal | optCaptureBpf
	}
	if t.config.Capture.Mem {
		cOptVal = cOptVal | optExtractDynCode
	}
	switch t.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		cOptVal = cOptVal | optCgroupV1
	}
	if t.config.Output.ParseArgumentsFDs {
		cOptVal = cOptVal | optTranslateFDFilePath
	}
	switch t.config.ProcTree.Source {
	case proctree.SourceBoth, proctree.SourceEvents:
		cOptVal = cOptVal | optForkProcTree // tell sched_process_fork to be prolix
	}

	return cOptVal
}

// newConfig returns a new Config instance based on the current Tracee state and
// the given policies config and version.
func (t *Tracee) newConfig(cfg *policy.PoliciesConfig) *Config {
	return &Config{
		TraceePid:       uint32(os.Getpid()),
		Options:         t.getOptionsConfig(),
		CgroupV1Hid:     uint32(t.cgroups.GetDefaultCgroupHierarchyID()),
		PoliciesVersion: 1, // version will be removed soon
		PoliciesConfig:  *cfg,
	}
}

func (t *Tracee) initKsymTableRequiredSyms() error {
	// Get all required symbols needed in the table
	// 1. all event ksym dependencies
	// 2. specific cases (hooked_seq_ops, hooked_symbols, print_mem_dump)
	for _, id := range t.policyManager.EventsSelected() {
		if !events.Core.IsDefined(id) {
			return errfmt.Errorf("event %d is not defined", id)
		}

		depsNode, err := t.eventsDependencies.GetEvent(id)
		if err != nil {
			logger.Warnw("failed to extract required ksymbols from event", "event_id", id, "error", err)
			continue
		}
		// Add directly dependant symbols
		deps := depsNode.GetDependencies()
		ksyms := deps.GetKSymbols()
		ksymNames := make([]string, 0, len(ksyms))
		for _, sym := range ksyms {
			ksymNames = append(ksymNames, sym.GetSymbolName())
		}
		t.requiredKsyms = append(t.requiredKsyms, ksymNames...)

		// If kprobe/kretprobe, the event name itself is a required symbol
		depsProbes := deps.GetProbes()
		for _, probeDep := range depsProbes {
			probe := t.defaultProbes.GetProbeByHandle(probeDep.GetHandle())
			traceProbe, ok := probe.(*probes.TraceProbe)
			if !ok {
				continue
			}
			probeType := traceProbe.GetProbeType()
			switch probeType {
			case probes.KProbe, probes.KretProbe:
				t.requiredKsyms = append(t.requiredKsyms, traceProbe.GetEventName())
			}
		}
	}

	// Specific cases
	if t.policyManager.IsEventSelected(events.HookedSeqOps) {
		for _, seqName := range derive.NetSeqOps {
			t.requiredKsyms = append(t.requiredKsyms, seqName)
		}
	}
	if t.policyManager.IsEventSelected(events.HookedSyscall) {
		t.requiredKsyms = append(t.requiredKsyms, events.SyscallPrefix+"ni_syscall", "sys_ni_syscall")
		for i, kernelRestrictionArr := range events.SyscallSymbolNames {
			syscallName := t.getSyscallNameByKerVer(kernelRestrictionArr)
			if syscallName == "" || strings.HasPrefix(syscallName, events.SyscallNotImplemented) {
				logger.Debugw("hooked_syscall (symbol): skipping syscall", "index", i)
				continue
			}

			t.requiredKsyms = append(t.requiredKsyms, events.SyscallPrefix+syscallName)
		}
	}
	if t.policyManager.IsEventSelected(events.PrintMemDump) {
		for it := t.policyManager.CreateAllIterator(); it.HasNext(); {
			p := it.Next()
			// This might break in the future if PrintMemDump will become a dependency of another event.
			_, isSelected := p.Rules[events.PrintMemDump]
			if !isSelected {
				continue
			}
			printMemDumpFilters := p.Rules[events.PrintMemDump].DataFilter.GetFieldFilters()
			if len(printMemDumpFilters) == 0 {
				continue
			}
			symbolsFilter, ok := printMemDumpFilters["symbol_name"].(*filters.StringFilter)
			if symbolsFilter == nil || !ok {
				continue
			}

			for _, field := range symbolsFilter.Equal() {
				symbolSlice := strings.Split(field, ":")
				splittedLen := len(symbolSlice)
				var name string
				if splittedLen == 1 {
					name = symbolSlice[0]
				} else if splittedLen == 2 {
					name = symbolSlice[1]
				} else {
					continue
				}
				t.requiredKsyms = append(
					t.requiredKsyms,
					// symbols
					name,
					"sys_"+name,
					events.SyscallPrefix+name,
				)
			}
		}
	}
	return nil
}

// getUnavailbaleKsymbols return all kernel symbols missing from given symbols
func getUnavailbaleKsymbols(ksymbols []events.KSymbol, kernelSymbols *environment.KernelSymbolTable) []events.KSymbol {
	var unavailableSymbols []events.KSymbol

	for _, ksymbol := range ksymbols {
		sym, err := kernelSymbols.GetSymbolByName(ksymbol.GetSymbolName())
		if err != nil {
			// If the symbol is not found, it means it's unavailable.
			unavailableSymbols = append(unavailableSymbols, ksymbol)
			continue
		}
		for _, s := range sym {
			if s.Address == 0 {
				// Same if the symbol is found but its address is 0.
				unavailableSymbols = append(unavailableSymbols, ksymbol)
			}
		}
	}
	return unavailableSymbols
}

// validateKallsymsDependencies load all symbols required by events dependencies
// from the kallsyms file to check for missing symbols. If some symbols are
// missing, it will cancel their event with informative error message.
func (t *Tracee) validateKallsymsDependencies() {
	evtDefSymDeps := func(id events.ID) []events.KSymbol {
		depsNode, err := t.eventsDependencies.GetEvent(id)
		if err != nil {
			logger.Debugw("Failed to get dependencies for event", "id", id, "error", err)
			return nil
		}
		deps := depsNode.GetDependencies()
		return deps.GetKSymbols()
	}

	validateEvent := func(eventId events.ID) bool {
		missingDepSyms := getUnavailbaleKsymbols(evtDefSymDeps(eventId), t.kernelSymbols)
		shouldFailEvent := false
		for _, symDep := range missingDepSyms {
			if symDep.IsRequired() {
				shouldFailEvent = true
				break
			}
		}
		if shouldFailEvent {
			eventNameToCancel := events.Core.GetDefinitionByID(eventId).GetName()
			var missingSymsNames []string
			for _, symDep := range missingDepSyms {
				missingSymsNames = append(missingSymsNames, symDep.GetSymbolName())
			}
			logger.Warnw(
				"Event canceled because of missing kernel symbol dependency",
				"missing symbols", missingSymsNames, "event", eventNameToCancel,
			)
			return false
		}
		return true
	}

	t.eventsDependencies.SubscribeAdd(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			if !validateEvent(eventNode.GetID()) {
				return []dependencies.Action{dependencies.NewCancelNodeAddAction(fmt.Errorf("event is missing ksymbols"))}
			}
			return nil
		})

	for _, eventId := range t.policyManager.EventsSelected() {
		if !validateEvent(eventId) {
			// Cancel the event, its dependencies and its dependent events
			err := t.eventsDependencies.RemoveEvent(eventId)
			if err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "missing ksymbols", "error", err)
			}
		}
	}
}

func (t *Tracee) populateBPFMaps() error {
	// Prepare 32bit to 64bit syscall number mapping
	sys32to64BPFMap, err := t.bpfModule.GetMap("sys_32_to_64_map") // u32, u32
	if err != nil {
		return errfmt.WrapError(err)
	}
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id32BitU32 := uint32(eventDefinition.GetID32Bit()) // ID32Bit is int32
		idU32 := uint32(eventDefinition.GetID())           // ID is int32
		err := sys32to64BPFMap.Update(unsafe.Pointer(&id32BitU32), unsafe.Pointer(&idU32))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Update the kallsyms eBPF map with all symbols from the kallsyms file.
	err = t.UpdateKallsyms()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize kconfig ebpf map with values from the kernel config file.
	// TODO: remove this from libbpf and try to rely in libbpf only for kconfig vars.
	bpfKConfigMap, err := t.bpfModule.GetMap("kconfig_map") // u32, u32
	if err != nil {
		return errfmt.WrapError(err)
	}
	kconfigValues, err := initialization.LoadKconfigValues(t.config.KernelConfig)
	if err != nil {
		return errfmt.WrapError(err)
	}
	for key, value := range kconfigValues {
		keyU32 := uint32(key)
		valueU32 := uint32(value)
		err = bpfKConfigMap.Update(unsafe.Pointer(&keyU32), unsafe.Pointer(&valueU32))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize the net_packet configuration eBPF map.
	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		bpfNetConfigMap, err := t.bpfModule.GetMap("netconfig_map")
		if err != nil {
			return errfmt.WrapError(err)
		}

		netConfigVal := make([]byte, 8) // u32 capture_options + u32 capture_length
		options := pcaps.GetPcapOptions(t.config.Capture.Net)
		binary.LittleEndian.PutUint32(netConfigVal[0:4], uint32(options))
		binary.LittleEndian.PutUint32(netConfigVal[4:8], t.config.Capture.Net.CaptureLength)

		cZero := uint32(0)
		err = bpfNetConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(&netConfigVal[0]))
		if err != nil {
			return errfmt.Errorf("error updating net config eBPF map: %v", err)
		}
	}

	// Initialize config and filter maps
	err = t.populateFilterMaps(false)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Populate containers map with existing containers
	err = t.containers.PopulateBpfMap(t.bpfModule)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Set filters given by the user to filter file write events
	fileWritePathFilterMap, err := t.bpfModule.GetMap("file_write_path_filter") // u32, u32
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(t.config.Capture.FileWrite.PathFilter)); i++ {
		filterFilePathWriteBytes := []byte(t.config.Capture.FileWrite.PathFilter[i])
		if err = fileWritePathFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&filterFilePathWriteBytes[0])); err != nil {
			return err
		}
	}

	// Set filters given by the user to filter file read events
	fileReadPathFilterMap, err := t.bpfModule.GetMap("file_read_path_filter") // u32, u32
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(t.config.Capture.FileRead.PathFilter)); i++ {
		filterFilePathReadBytes := []byte(t.config.Capture.FileRead.PathFilter[i])
		if err = fileReadPathFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&filterFilePathReadBytes[0])); err != nil {
			return err
		}
	}

	// Set filters given by the user to filter file read and write type and fds
	fileTypeFilterMap, err := t.bpfModule.GetMap("file_type_filter") // u32, u32
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Should match the value of CAPTURE_READ_TYPE_FILTER_IDX in eBPF code
	captureReadTypeFilterIndex := uint32(0)
	captureReadTypeFilterVal := uint32(t.config.Capture.FileRead.TypeFilter)
	if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureReadTypeFilterIndex),
		unsafe.Pointer(&captureReadTypeFilterVal)); err != nil {
		return errfmt.WrapError(err)
	}

	// Should match the value of CAPTURE_WRITE_TYPE_FILTER_IDX in eBPF code
	captureWriteTypeFilterIndex := uint32(1)
	captureWriteTypeFilterVal := uint32(t.config.Capture.FileWrite.TypeFilter)
	if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureWriteTypeFilterIndex),
		unsafe.Pointer(&captureWriteTypeFilterVal)); err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize tail call dependencies
	eventsToSubmit := t.policyManager.EventsToSubmit()
	tailCalls := events.Core.GetTailCalls(eventsToSubmit)
	for _, tailCall := range tailCalls {
		err := t.initTailCall(tailCall)
		if err != nil {
			return errfmt.Errorf("failed to initialize tail call: %v", err)
		}
	}

	return nil
}

// populateFilterMaps populates the eBPF maps with the given policies
func (t *Tracee) populateFilterMaps(updateProcTree bool) error {
	polCfg, err := t.policyManager.UpdateBPF(
		t.bpfModule,
		t.containers,
		t.eventsFieldTypes,
		true,
		updateProcTree,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Create new config with updated policies and update eBPF map

	cfg := t.newConfig(polCfg)
	if err := cfg.UpdateBPF(t.bpfModule); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// attachEvent attaches the probes of the given event to their respective eBPF programs.
// Calling attachment of probes if a supported behavior, and will do nothing
// if it has been attached already.
// Return whether the event was successfully attached or not.
func (t *Tracee) attachEvent(id events.ID) error {
	evtName := events.Core.GetDefinitionByID(id).GetName()
	depsNode, err := t.eventsDependencies.GetEvent(id)
	if err != nil {
		logger.Errorw("Missing event in dependencies", "event", evtName)
		return err
	}
	for _, probe := range depsNode.GetDependencies().GetProbes() {
		err := t.defaultProbes.Attach(probe.GetHandle(), t.cgroups, t.kernelSymbols)
		if err == nil {
			continue
		}
		if probe.IsRequired() {
			logger.Warnw(
				"Cancelling event and its dependencies because of a missing probe",
				"missing probe", probe.GetHandle(), "event", evtName,
				"error", err,
			)
			return err
		}
		logger.Debugw(
			"Failed to attach non-required probe for event",
			"event", evtName,
			"probe", probe.GetHandle(), "error", err,
		)
	}
	return nil
}

// attachProbes attaches selected events probes to their respective eBPF programs.
func (t *Tracee) attachProbes() error {
	// Subscribe to all watchers on the dependencies to attach and/or detach
	// probes upon changes
	t.eventsDependencies.SubscribeAdd(
		dependencies.ProbeNodeType,
		func(node interface{}) []dependencies.Action {
			probeNode, ok := node.(*dependencies.ProbeNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			err := t.defaultProbes.Attach(probeNode.GetHandle(), t.cgroups, t.kernelSymbols)
			if err != nil {
				return []dependencies.Action{dependencies.NewCancelNodeAddAction(err)}
			}
			return nil
		})

	t.eventsDependencies.SubscribeRemove(
		dependencies.ProbeNodeType,
		func(node interface{}) []dependencies.Action {
			probeNode, ok := node.(*dependencies.ProbeNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			err := t.defaultProbes.Detach(probeNode.GetHandle())
			if err != nil {
				logger.Debugw("Failed to detach probe",
					"probe", probeNode.GetHandle(),
					"error", err)
			}
			return nil
		})

	// Attach probes to their respective eBPF programs or cancel events if a required probe is missing.
	for _, eventID := range t.policyManager.EventsSelected() {
		err := t.attachEvent(eventID)
		if err != nil {
			err := t.eventsDependencies.RemoveEvent(eventID)
			if err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "failed probes attachment", "error", err)
			}
		}
	}
	// TODO: Update the eBPF maps according to events state after failure of attachments
	return nil
}

func (t *Tracee) initBPFProbes() error {
	var err error
	// Execute code with higher privileges: ring1 (required)

	newModuleArgs := bpf.NewModuleArgs{
		KConfigFilePath: t.config.KernelConfig.GetKernelConfigFilePath(),
		BTFObjPath:      t.config.BTFObjPath,
		BPFObjBuff:      t.config.BPFObjBytes,
	}

	// Open the eBPF object file (create a new module)

	t.bpfModule, err = bpf.NewModuleFromBufferArgs(newModuleArgs)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize probes

	t.defaultProbes, err = probes.NewDefaultProbeGroup(t.bpfModule, t.netEnabled())
	if err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

func (t *Tracee) initBPF() error {
	var err error

	// Load the eBPF object into kernel

	err = t.bpfModule.BPFLoadObject()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Need to force nil to allow the garbage
	// collector to free the BPF object
	t.config.BPFObjBytes = nil

	// Populate eBPF maps with initial data

	err = t.populateBPFMaps()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize Control Plane

	t.controlPlane, err = controlplane.NewController(
		t.bpfModule,
		t.containers,
		t.config.NoContainersEnrich,
		t.processTree,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// returned PoliciesConfig is not used here, therefore it's discarded
	_, err = t.policyManager.UpdateBPF(t.bpfModule, t.containers, t.eventsFieldTypes, false, true)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize perf buffers and needed channels

	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	if t.config.PerfBufferSize < 1 {
		return errfmt.Errorf("invalid perf buffer size: %d", t.config.PerfBufferSize)
	}
	t.eventsPerfMap, err = t.bpfModule.InitPerfBuf(
		"events",
		t.eventsChannel,
		t.lostEvChannel,
		t.config.PerfBufferSize,
	)
	if err != nil {
		return errfmt.Errorf("error initializing events perf map: %v", err)
	}

	if t.config.BlobPerfBufferSize > 0 {
		t.fileCapturesChannel = make(chan []byte, 1000)
		t.lostCapturesChannel = make(chan uint64)
		t.fileWrPerfMap, err = t.bpfModule.InitPerfBuf(
			"file_writes",
			t.fileCapturesChannel,
			t.lostCapturesChannel,
			t.config.BlobPerfBufferSize,
		)
		if err != nil {
			return errfmt.Errorf("error initializing file_writes perf map: %v", err)
		}
	}

	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		t.netCapChannel = make(chan []byte, 1000)
		t.lostNetCapChannel = make(chan uint64)
		t.netCapPerfMap, err = t.bpfModule.InitPerfBuf(
			"net_cap_events",
			t.netCapChannel,
			t.lostNetCapChannel,
			t.config.PerfBufferSize,
		)
		if err != nil {
			return errfmt.Errorf("error initializing net capture perf map: %v", err)
		}
	}

	t.bpfLogsChannel = make(chan []byte, 1000)
	t.lostBPFLogChannel = make(chan uint64)
	t.bpfLogsPerfMap, err = t.bpfModule.InitPerfBuf(
		"logs",
		t.bpfLogsChannel,
		t.lostBPFLogChannel,
		t.config.PerfBufferSize,
	)
	if err != nil {
		return errfmt.Errorf("error initializing logs perf map: %v", err)
	}

	// Attach eBPF programs to selected event's probes

	// TODO: Solve race window between ProcessTreeFilters initialization through procfs and the
	// attachment of the probes that update the filters from the eBPF side. Maybe perform another
	// iteration on procfs to fill in any missing data.

	err = t.attachProbes()

	return errfmt.WrapError(err)
}

const pollTimeout int = 300

// Run starts the trace. it will run until ctx is cancelled
func (t *Tracee) Run(ctx gocontext.Context) error {
	// Some events need initialization before the perf buffers are polled

	go t.hookedSyscallTableRoutine(ctx)

	t.triggerSeqOpsIntegrityCheck(trace.Event{})
	errs := t.triggerMemDump(trace.Event{})
	for _, err := range errs {
		logger.Warnw("Memory dump", "error", err)
	}

	go t.lkmSeekerRoutine(ctx)

	// Start control plane
	t.controlPlane.Start()
	go t.controlPlane.Run(ctx)

	// Measure event perf buffer write attempts (METRICS build only)

	if version.MetricsBuild() {
		go t.countPerfEventSubmissions(ctx)
	}

	// Main event loop (polling events perf buffer)

	t.eventsPerfMap.Poll(pollTimeout)

	pipelineReady := make(chan struct{}, 1)
	go t.processLostEvents() // termination signaled by closing t.done
	go t.handleEvents(ctx, pipelineReady)

	// Parallel perf buffer with file writes events

	if t.config.BlobPerfBufferSize > 0 {
		t.fileWrPerfMap.Poll(pollTimeout)
		go t.handleFileCaptures(ctx)
	}

	// Network capture perf buffer (similar to regular pipeline)

	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		t.netCapPerfMap.Poll(pollTimeout)
		go t.handleNetCaptureEvents(ctx)
	}

	// Logging perf buffer

	t.bpfLogsPerfMap.Poll(pollTimeout)
	go t.processBPFLogs(ctx)

	// Management

	<-pipelineReady
	t.running.Store(true) // set running state after writing pid file
	t.ready(ctx)          // executes ready callback, non blocking
	<-ctx.Done()          // block until ctx is cancelled elsewhere

	// Close perf buffers

	t.eventsPerfMap.Close()
	if t.config.BlobPerfBufferSize > 0 {
		t.fileWrPerfMap.Close()
	}
	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		t.netCapPerfMap.Close()
	}
	t.bpfLogsPerfMap.Close()

	// TODO: move logic below somewhere else (related to file writes)

	// record index of written files
	if t.config.Capture.FileWrite.Capture {
		err := updateCaptureMapFile(t.OutDir, "written_files", t.writtenFiles, t.config.Capture.FileWrite)
		if err != nil {
			return err
		}
	}

	// record index of read files
	if t.config.Capture.FileRead.Capture {
		err := updateCaptureMapFile(t.OutDir, "read_files", t.readFiles, t.config.Capture.FileRead)
		if err != nil {
			return err
		}
	}

	t.Close() // close Tracee

	return nil
}

func updateCaptureMapFile(fileDir *os.File, filePath string, capturedFiles map[string]string, cfg config.FileCaptureConfig) error {
	f, err := utils.OpenAt(fileDir, filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errfmt.Errorf("error logging captured files")
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	for fileName, filePath := range capturedFiles {
		captureFiltered := false
		// TODO: We need a method to decide if the capture was filtered by FD or type.
		for _, filterPrefix := range cfg.PathFilter {
			if !strings.HasPrefix(filePath, filterPrefix) {
				captureFiltered = true
				break
			}
		}
		if captureFiltered {
			// Don't write mapping of files that were not actually captured
			continue
		}
		if _, err := f.WriteString(fmt.Sprintf("%s %s\n", fileName, filePath)); err != nil {
			return errfmt.Errorf("error logging captured files")
		}
	}
	return nil
}

// Close cleans up created resources
func (t *Tracee) Close() {
	// clean up (unsubscribe) all streams connected if tracee is done
	if t.streamsManager != nil {
		t.streamsManager.Close()
	}
	if t.controlPlane != nil {
		err := t.controlPlane.Stop()
		if err != nil {
			logger.Errorw("failed to stop control plane when closing tracee", "err", err)
		}
	}
	if t.defaultProbes != nil {
		err := t.defaultProbes.DetachAll()
		if err != nil {
			logger.Errorw("failed to detach default probes when closing tracee", "err", err)
		}
	}
	for name, probeGroup := range t.extraProbes {
		err := probeGroup.DetachAll()
		if err != nil {
			logger.Errorw("failed to detach probes when closing tracee", "probe group", name, "err", err)
		}
	}
	if t.bpfModule != nil {
		t.bpfModule.Close()
	}
	if t.containers != nil {
		err := t.containers.Close()
		if err != nil {
			logger.Errorw("failed to clean containers module when closing tracee", "err", err)
		}
	}
	if err := t.cgroups.Destroy(); err != nil {
		logger.Errorw("Cgroups destroy", "error", err)
	}

	// set 'running' to false and close 'done' channel only after attempting to close all resources
	t.running.Store(false)
	close(t.done)
}

// Running returns true if the tracee is running
func (t *Tracee) Running() bool {
	return t.running.Load()
}

func (t *Tracee) computeOutFileHash(fileName string) (string, error) {
	f, err := utils.OpenAt(t.OutDir, fileName, os.O_RDONLY, 0)
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	return filehash.ComputeFileHash(f)
}

// getSelfLoadedPrograms returns a map of all programs loaded by tracee.
func (t *Tracee) getSelfLoadedPrograms(kprobesOnly bool) map[string]int {
	selfLoadedPrograms := map[string]int{} // map k: symbol name, v: number of hooks

	log := func(event string, program string) {
		logger.Debugw("self loaded program", "event", event, "program", program)
	}

	type probeMapKey struct {
		programName string
		eventName   string
		probeType   probes.ProbeType
	}
	// We need to count how many ftrace based hooks will be placed on each symbol.
	// eventsState may contain duplicate events due to dependencies.
	// To get the real count, we consider the program name and the prob type.
	// For example:
	// event state may contain the following entries:
	// eventName: do_init_module, programName: trace_do_init_module, probtype: 0, definitionID: 778
	// eventName: do_init_module, programName: trace_ret_do_init_module, probtype: 1, definitionID: 778
	// eventName: do_init_module, programName: trace_do_init_module, probtype: 0, definitionID: 760
	// eventName: do_init_module, programName: trace_ret_do_init_module, probtype: 1, definitionID: 760
	// Even though there are 4 entries, we can see that only 2 hooks are going to be placed in practice.
	// The symbol is do_init_module: kprobe with the program trace_do_init_module, kretprobe with the program trace_ret_do_init_module
	uniqueHooksMap := map[probeMapKey]struct{}{}

	for _, tr := range t.policyManager.EventsSelected() {
		if !events.Core.IsDefined(tr) {
			continue
		}

		definition := events.Core.GetDefinitionByID(tr)

		for _, depProbes := range definition.GetDependencies().GetProbes() {
			currProbe := t.defaultProbes.GetProbeByHandle(depProbes.GetHandle())
			name := ""
			switch p := currProbe.(type) {
			case *probes.TraceProbe:
				// Only k[ret]probes may use ftrace
				if kprobesOnly {
					switch p.GetProbeType() {
					case probes.KProbe, probes.KretProbe:
					default:
						continue
					}
				}
				if !p.IsAttached() {
					// Don't fill the map with entries that didn't get hook (missing symbol etc)
					continue
				}
				key := probeMapKey{
					programName: p.GetProgramName(),
					probeType:   p.GetProbeType(),
					eventName:   p.GetEventName(),
				}

				_, found := uniqueHooksMap[key]
				if found { // Already counted this hook
					continue
				}

				uniqueHooksMap[key] = struct{}{}

				log(definition.GetName(), p.GetProgramName())
				name = p.GetEventName()
			case *probes.Uprobe:
				log(definition.GetName(), p.GetProgramName())
				continue
			case *probes.CgroupProbe:
				log(definition.GetName(), p.GetProgramName())
				continue
			default:
				continue
			}

			selfLoadedPrograms[name]++
		}
	}

	return selfLoadedPrograms
}

// invokeInitEvents emits Tracee events, called Initialization Events, that are generated from the
// userland process itself, and not from the kernel. These events usually serve as informational
// events for the signatures engine/logic.
func (t *Tracee) invokeInitEvents(out chan *trace.Event) {
	var matchedPolicies uint64

	setMatchedPolicies := func(event *trace.Event, matchedPolicies uint64) {
		event.PoliciesVersion = 1 // version will be removed soon
		event.MatchedPoliciesKernel = matchedPolicies
		event.MatchedPoliciesUser = matchedPolicies
		event.MatchedPolicies = t.policyManager.MatchedNames(matchedPolicies)
	}

	policiesMatch := func(id events.ID) uint64 {
		return t.policyManager.MatchEventInAnyPolicy(id)
	}

	// Initial namespace events

	matchedPolicies = policiesMatch(events.TraceeInfo)
	if matchedPolicies > 0 {
		traceeDataEvent := events.TraceeInfoEvent(t.bootTime, t.startTime)
		setMatchedPolicies(&traceeDataEvent, matchedPolicies)
		out <- &traceeDataEvent
		_ = t.stats.EventCount.Increment()
	}

	matchedPolicies = policiesMatch(events.InitNamespaces)
	if matchedPolicies > 0 {
		systemInfoEvent := events.InitNamespacesEvent()
		setMatchedPolicies(&systemInfoEvent, matchedPolicies)
		out <- &systemInfoEvent
		_ = t.stats.EventCount.Increment()
	}

	// Initial existing containers events (1 event per container)

	matchedPolicies = policiesMatch(events.ExistingContainer)
	if matchedPolicies > 0 {
		existingContainerEvents := events.ExistingContainersEvents(t.containers, t.config.NoContainersEnrich)
		for i := range existingContainerEvents {
			event := &(existingContainerEvents[i])
			setMatchedPolicies(event, matchedPolicies)
			out <- event
			_ = t.stats.EventCount.Increment()
		}
	}

	// Ftrace hook event

	matchedPolicies = policiesMatch(events.FtraceHook)
	if matchedPolicies > 0 {
		ftraceBaseEvent := events.GetFtraceBaseEvent()
		setMatchedPolicies(ftraceBaseEvent, matchedPolicies)
		logger.Debugw("started ftraceHook goroutine")

		// TODO: Ideally, this should be inside the goroutine and be computed before each run,
		// as in the future tracee events may be changed in run time.
		// Currently, moving it inside the goroutine leads to a circular importing due to
		// eventsState (which is used inside the goroutine).
		// eventsState is planned to be removed, and this call should move inside the routine
		// once that happens.
		selfLoadedFtraceProgs := t.getSelfLoadedPrograms(true)

		go events.FtraceHookEvent(t.stats.EventCount, out, ftraceBaseEvent, selfLoadedFtraceProgs)
	}
}

// netEnabled returns true if any base network event is to be traced
func (t *Tracee) netEnabled() bool {
	for _, id := range t.policyManager.EventsSelected() {
		if id >= events.NetPacketBase && id <= events.MaxNetID {
			return true
		}
	}

	// if called before capture meta-events are set to be traced:
	return pcaps.PcapsEnabled(t.config.Capture.Net)
}

//
// TODO: move to triggerEvents package
//

// triggerSeqOpsIntegrityCheck is used by a Uprobe to trigger an eBPF program
// that prints the seq ops pointers
func (t *Tracee) triggerSeqOpsIntegrityCheck(event trace.Event) {
	if !t.policyManager.IsEventSelected(events.HookedSeqOps) {
		return
	}
	var seqOpsPointers [len(derive.NetSeqOps)]uint64
	for i, seqName := range derive.NetSeqOps {
		seqOpsStruct, err := t.kernelSymbols.GetSymbolByOwnerAndName("system", seqName)
		if err != nil {
			continue
		}
		seqOpsPointers[i] = seqOpsStruct[0].Address
	}
	eventHandle := t.triggerContexts.Store(event)
	_ = t.triggerSeqOpsIntegrityCheckCall(
		uint64(eventHandle),
		seqOpsPointers,
	)
}

//go:noinline
func (t *Tracee) triggerSeqOpsIntegrityCheckCall(
	eventHandle uint64,
	seqOpsStruct [len(derive.NetSeqOps)]uint64) error {
	return nil
}

// triggerMemDump is used by a Uprobe to trigger an eBPF program
// that prints the first bytes of requested symbols or addresses
func (t *Tracee) triggerMemDump(event trace.Event) []error {
	if !t.policyManager.IsEventSelected(events.PrintMemDump) {
		return nil
	}

	var errs []error

	for it := t.policyManager.CreateAllIterator(); it.HasNext(); {
		p := it.Next()
		// This might break in the future if PrintMemDump will become a dependency of another event.
		_, isSelected := p.Rules[events.PrintMemDump]
		if !isSelected {
			continue
		}
		printMemDumpFilters := p.Rules[events.PrintMemDump].DataFilter.GetFieldFilters()
		if len(printMemDumpFilters) == 0 {
			errs = append(errs, errfmt.Errorf("policy %d: no address or symbols were provided to print_mem_dump event. "+
				"please provide it via -e print_mem_dump.data.address=<hex address>"+
				", -e print_mem_dump.data.symbol_name=<owner>:<symbol> or "+
				"-e print_mem_dump.data.symbol_name=<symbol> if specifying a system owned symbol", p.ID))

			continue
		}

		var length uint64
		var err error

		lengthFilter, ok := printMemDumpFilters["length"].(*filters.StringFilter)
		if lengthFilter == nil || !ok || len(lengthFilter.Equal()) == 0 {
			length = maxMemDumpLength // default mem dump length
		} else {
			field := lengthFilter.Equal()[0]
			length, err = strconv.ParseUint(field, 10, 64)
			if err != nil {
				errs = append(errs, errfmt.Errorf("policy %d: invalid length provided to print_mem_dump event: %v", p.ID, err))

				continue
			}
		}

		addressFilter, ok := printMemDumpFilters["address"].(*filters.StringFilter)
		if addressFilter != nil && ok {
			for _, field := range addressFilter.Equal() {
				address, err := strconv.ParseUint(field, 16, 64)
				if err != nil {
					errs[p.ID] = errfmt.Errorf("policy %d: invalid address provided to print_mem_dump event: %v", p.ID, err)

					continue
				}
				eventHandle := t.triggerContexts.Store(event)
				_ = t.triggerMemDumpCall(address, length, eventHandle)
			}
		}

		symbolsFilter, ok := printMemDumpFilters["symbol_name"].(*filters.StringFilter)
		if symbolsFilter != nil && ok {
			for _, field := range symbolsFilter.Equal() {
				symbolSlice := strings.Split(field, ":")
				splittedLen := len(symbolSlice)
				var owner string
				var name string
				if splittedLen == 1 {
					owner = "system"
					name = symbolSlice[0]
				} else if splittedLen == 2 {
					owner = symbolSlice[0]
					name = symbolSlice[1]
				} else {
					errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - more than one ':' provided", p.ID, field))

					continue
				}
				symbol, err := t.kernelSymbols.GetSymbolByOwnerAndName(owner, name)
				if err != nil {
					if owner != "system" {
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - %v", p.ID, field, err))

						continue
					}

					// Checking if the user specified a syscall name
					prefixes := []string{"sys_", "__x64_sys_", "__arm64_sys_"}
					var errSyscall error
					for _, prefix := range prefixes {
						symbol, errSyscall = t.kernelSymbols.GetSymbolByOwnerAndName(owner, prefix+name)
						if errSyscall == nil {
							err = nil
							break
						}
					}
					if err != nil {
						// syscall not found for the given name using all the prefixes
						valuesStr := make([]string, 0)
						valuesStr = append(valuesStr, owner+"_")
						valuesStr = append(valuesStr, prefixes...)
						valuesStr = append(valuesStr, name)

						values := make([]interface{}, len(valuesStr))
						for i, v := range valuesStr {
							values[i] = v
						}
						attemptedSymbols := fmt.Sprintf("{%s,%s,%s,%s}%s", values...)
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s", p.ID, attemptedSymbols))

						continue
					}
				}
				eventHandle := t.triggerContexts.Store(event)
				_ = t.triggerMemDumpCall(symbol[0].Address, length, uint64(eventHandle))
			}
		}
	}

	return errs
}

// AddReadyCallback sets a callback function to be called when the tracee started all its probes
// and is ready to receive events
func (t *Tracee) AddReadyCallback(f func(ctx gocontext.Context)) {
	t.readyCallback = f
}

// ready executes the ready callback if it was set.
// doesn't block the execution of the tracee
func (t *Tracee) ready(ctx gocontext.Context) {
	if t.readyCallback != nil {
		go t.readyCallback(ctx)
	}
}

//go:noinline
func (t *Tracee) triggerMemDumpCall(address uint64, length uint64, eventHandle uint64) error {
	return nil
}

// SubscribeAll returns a stream subscribed to all policies
func (t *Tracee) SubscribeAll() *streams.Stream {
	return t.subscribe(policy.PolicyAll)
}

// Subscribe returns a stream subscribed to selected policies
func (t *Tracee) Subscribe(policyNames []string) (*streams.Stream, error) {
	var policyMask uint64

	for _, policyName := range policyNames {
		p, err := t.policyManager.LookupByName(policyName)
		if err != nil {
			return nil, err
		}
		utils.SetBit(&policyMask, uint(p.ID))
	}

	return t.subscribe(policyMask), nil
}

func (t *Tracee) subscribe(policyMask uint64) *streams.Stream {
	// TODO: the channel size matches the pipeline channel size,
	// but we should make it configurable in the future.
	return t.streamsManager.Subscribe(policyMask, t.config.PipelineChannelSize)
}

// Unsubscribe unsubscribes stream
func (t *Tracee) Unsubscribe(s *streams.Stream) {
	t.streamsManager.Unsubscribe(s)
}

func (t *Tracee) EnableEvent(eventName string) error {
	id, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	t.policyManager.EnableEvent(id)

	return nil
}

func (t *Tracee) DisableEvent(eventName string) error {
	id, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	t.policyManager.DisableEvent(id)

	return nil
}

// EnableRule enables a rule in the specified policies
func (t *Tracee) EnableRule(policyNames []string, ruleId string) error {
	eventID, found := events.Core.GetDefinitionIDByName(ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	for _, policyName := range policyNames {
		p, err := t.policyManager.LookupByName(policyName)
		if err != nil {
			return err
		}

		err = t.policyManager.EnableRule(p.ID, eventID)
		if err != nil {
			return err
		}
	}

	return nil
}

// DisableRule disables a rule in the specified policies
func (t *Tracee) DisableRule(policyNames []string, ruleId string) error {
	eventID, found := events.Core.GetDefinitionIDByName(ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	for _, policyName := range policyNames {
		p, err := t.policyManager.LookupByName(policyName)
		if err != nil {
			return err
		}

		err = t.policyManager.DisableRule(p.ID, eventID)
		if err != nil {
			return err
		}
	}

	return nil
}
