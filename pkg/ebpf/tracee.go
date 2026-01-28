package ebpf

import (
	gocontext "context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/api/v1beta1"
	dsapi "github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/common/bucketcache"
	"github.com/aquasecurity/tracee/common/capabilities"
	"github.com/aquasecurity/tracee/common/cgroup"
	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/fileutil"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/proc"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/datastores/symbol"
	"github.com/aquasecurity/tracee/pkg/datastores/syscall"
	"github.com/aquasecurity/tracee/pkg/datastores/system"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/ebpf/controlplane"
	"github.com/aquasecurity/tracee/pkg/ebpf/initialization"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/events/sorting"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	pkgName          = "tracee"
	maxMemDumpLength = 127
)

// populateE2eRegistrations is overridden by e2e build-tagged files to populate e2e registrations.
// Default no-op implementation for non-e2e builds.
var populateE2eRegistrations = func(t *Tracee) {}

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config    config.Config
	bootTime  uint64
	startTime uint64
	running   atomic.Bool
	done      chan struct{} // signal to safely stop end-stage processing
	OutDir    *os.File      // use common.XXX functions to create or write to this file
	stats     *metrics.Stats
	sigEngine *engine.Engine
	// Events
	eventsSorter     *sorting.EventsChronologicalSorter
	eventsPool       *sync.Pool
	eventDecodeTypes map[events.ID][]data.DecodeAs
	eventProcessor   map[events.ID][]func(evt *trace.Event) error
	eventDerivations derive.Table
	// Artifacts
	fileHashes     *digest.Cache
	artifactsFiles map[string]int64
	writtenFiles   map[string]string
	netCapturePcap *pcaps.Pcaps
	// Internal Data
	readFiles   map[string]string
	pidsInMntns bucketcache.BucketCache // first n PIDs in each mountns
	// eBPF
	bpfModule       *bpf.Module
	defaultProbes   *probes.ProbeGroup
	extraProbes     map[string]*probes.ProbeGroup
	dataTypeDecoder bufferdecoder.TypeDecoder
	kallsymsMutex   sync.Mutex // prevents concurrent UpdateKallsyms calls
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
	contPathResolver  *container.ContainerPathResolver
	contSymbolsLoader *container.ContainersSymbolsLoader
	// Control Plane
	controlPlane *controlplane.Controller
	// DataStore Registry Manager (provides both internal and public access).
	// Use GetXxx() methods for internal Tracee operations; use Registry() for detector access.
	dataStoreRegistry datastores.RegistryManager
	// E2e datastore registration function (set by build-tagged files via populateE2eRegistrations)
	registerE2eDatastoresFn func(dsapi.Registry) error
	// E2e gRPC service registration function (set by build-tagged files via populateE2eRegistrations)
	registerE2eGrpcServicesFn func(*grpc.Server, *Tracee)
	// Detector Engine
	detectorEngine *detectors.Engine
	// Specific Events Needs
	triggerContexts trigger.Context
	readyCallback   func(gocontext.Context)
	// Streams
	streamsManager *streams.StreamsManager
	// policyManager manages policy state
	policyManager *policy.Manager
	// The dependencies of events used by Tracee
	eventsDependencies *dependencies.Manager
	// A reference to a symbol.KernelSymbolTable that might change at runtime.
	// This should only be accessed using t.getKernelSymbols() and t.setKernelSymbols()
	kernelSymbols atomic.Pointer[symbol.KernelSymbolTable]
	// Ksymbols needed to be kept alive in table.
	// This does not mean they are required for tracee to function.
	// TODO: remove this in favor of dependency manager nodes
	requiredKsyms []string
	// Extensions manager
	extensions *Extensions
}

func (t *Tracee) Stats() *metrics.Stats {
	return t.stats
}

// initializeBPFEventsStatsMap initializes the events_stats BPF map with zero values
// and sets it for metrics collection
func (t *Tracee) initializeBPFEventsStatsMap() error {
	evtsStatsBPFMap, err := t.bpfModule.GetMap("events_stats")
	if err != nil {
		return errfmt.Errorf("failed to get events_stats map: %v", err)
	}

	// Set the map for metrics collection
	t.stats.SetPerfEventStatsMap(evtsStatsBPFMap)

	// eventStatsValues mirrors the C struct event_stats_values (event_stats_values_t)
	type eventStatsValues struct {
		submitAttempts uint64
		submitFailures uint64
	}

	evtStatZero := eventStatsValues{}
	for _, id := range t.policyManager.EventsToSubmit() {
		// Only initialize events that we want to track
		if !t.stats.ShouldTrackEventForBPFStats(id) {
			continue
		}

		key := uint32(id)
		err := evtsStatsBPFMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&evtStatZero))
		if err != nil {
			return errfmt.Errorf("failed to update events_stats map for event %d: %v", id, err)
		}
	}

	return nil
}

func (t *Tracee) Engine() *engine.Engine {
	return t.sigEngine
}

func (t *Tracee) getKernelSymbols() *symbol.KernelSymbolTable {
	return t.kernelSymbols.Load()
}

func (t *Tracee) setKernelSymbols(kernelSymbols *symbol.KernelSymbolTable) {
	t.kernelSymbols.Store(kernelSymbols)
}

// DataStores returns the datastore registry for accessing system state information
func (t *Tracee) DataStores() dsapi.Registry {
	return t.dataStoreRegistry.Registry()
}

// RegisterE2eGrpcServices calls the e2e gRPC service registration function if set
func (t *Tracee) RegisterE2eGrpcServices(grpcServer *grpc.Server) {
	if t.registerE2eGrpcServicesFn != nil {
		t.registerE2eGrpcServicesFn(grpcServer, t)
	}
}

// New creates a new Tracee instance based on a given valid Config. It is expected that it won't
// cause external system side effects (reads, writes, etc).
func New(cfg config.Config) (*Tracee, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, errfmt.Errorf("validation error: %v", err)
	}

	// Initialize capabilities rings soon

	useBaseEbpf := func(c config.Config) bool {
		return c.Output.UserStack
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
		func(id events.ID) events.DependencyStrategy {
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
	getNewArtifactsConfig := func() config.ArtifactsConfig {
		fileReadPathFilter := make([]string, 0, len(cfg.Artifacts.FileRead.PathFilter))
		copy(fileReadPathFilter, cfg.Artifacts.FileRead.PathFilter)
		fileRead := config.FileArtifactsConfig{
			Capture:    cfg.Artifacts.FileRead.Capture,
			PathFilter: fileReadPathFilter,
			TypeFilter: cfg.Artifacts.FileRead.TypeFilter,
		}

		fileWritePathFilter := make([]string, 0, len(cfg.Artifacts.FileWrite.PathFilter))
		copy(fileWritePathFilter, cfg.Artifacts.FileWrite.PathFilter)
		fileWrite := config.FileArtifactsConfig{
			Capture:    cfg.Artifacts.FileWrite.Capture,
			PathFilter: fileWritePathFilter,
			TypeFilter: cfg.Artifacts.FileWrite.TypeFilter,
		}

		return config.ArtifactsConfig{
			FileRead:  fileRead,
			FileWrite: fileWrite,
			Module:    cfg.Artifacts.Module,
			Exec:      cfg.Artifacts.Exec,
			Mem:       cfg.Artifacts.Mem,
			Bpf:       cfg.Artifacts.Bpf,
			Net:       cfg.Artifacts.Net,
		}
	}

	pmCfg := policy.ManagerConfig{
		HeartbeatEnabled:   cfg.HealthzEnabled,
		DNSStoreConfig:     cfg.DNSStore,
		ProcessStoreConfig: cfg.ProcessStore,
		ArtifactsConfig:    getNewArtifactsConfig(),
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
		artifactsFiles:     make(map[string]int64),
		streamsManager:     streams.NewStreamsManager(),
		policyManager:      pm,
		eventsDependencies: depsManager,
		requiredKsyms:      []string{},
		extraProbes:        make(map[string]*probes.ProbeGroup),
		dataTypeDecoder:    bufferdecoder.NewTypeDecoder(),
		extensions:         NewExtensions(),
	}

	// Allow e2e build-tagged files to set e2e registration functions
	if populateE2eRegistrations != nil {
		populateE2eRegistrations(t)
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

	// Initialize extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseStart); err != nil {
		return err
	}

	// Initialize buckets cache

	var mntNSProcs map[uint32]int32 // map[mntns]pid

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
			t.pidsInMntns.AddBucketItem(mountNS, uint32(pid))
		}
	} else {
		logger.Debugw("Initializing buckets cache", "error", errfmt.WrapError(err))
	}

	// Initialize cgroups filesystems

	t.cgroups, err = cgroup.NewCgroups(t.config.CgroupFSPath, t.config.CgroupFSForce)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize cgroups filesystems extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseCGroups); err != nil {
		return err
	}

	// Initialize containers enrichment logic

	containerMgr, err := container.New(
		t.config.EnrichmentEnabled,
		t.cgroups,
		t.config.Sockets,
		"containers_map",
	)
	if err != nil {
		return errfmt.Errorf("error initializing containers: %v", err)
	}

	// Initialize DNS Cache

	var dnsCache *dns.DNSCache
	if t.config.DNSStore.Enable {
		dnsCache, err = dns.New(t.config.DNSStore)
		if err != nil {
			return errfmt.Errorf("error initializing dns cache: %v", err)
		}
	}

	// Initialize containers related logic

	t.contPathResolver = container.InitContainerPathResolver(&t.pidsInMntns)
	t.contSymbolsLoader = container.InitContainersSymbolsLoader(t.contPathResolver, 1024)

	// Initialize containers related extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseContainers); err != nil {
		return err
	}

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

	// Initialize eBPF probes extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseBPFProbes); err != nil {
		return err
	}

	// Init kernel symbols map

	err = t.initKsymTableRequiredSyms()
	if err != nil {
		return err
	}

	err = capabilities.GetInstance().Specific(
		func() error {
			// t.requiredKsyms may contain non-data symbols, but it doesn't affect the validity of this call
			kernelSymbols, err := symbol.NewKernelSymbolTable(true, true, t.requiredKsyms...)
			if err != nil {
				return err
			}
			t.setKernelSymbols(kernelSymbols)
			return nil
		},
		cap.SYSLOG,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	t.validateKallsymsDependencies() // disable events w/ missing ksyms dependencies

	// Initialize kernel symbols extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseKernelSymbols); err != nil {
		return err
	}

	// Initialize Detector Engine
	enrichOpts := &detectors.EnrichmentOptions{
		Environment:  t.config.Output.Environment,
		ExecHashMode: t.config.Output.CalcHashes,
		Container:    t.config.EnrichmentEnabled,
	}
	t.detectorEngine = detectors.NewEngine(t.policyManager, enrichOpts)

	// Register detector metrics if metrics are enabled
	if t.MetricsEnabled() {
		if err := t.detectorEngine.RegisterPrometheusMetrics(); err != nil {
			logger.Errorw("Registering detector prometheus metrics", "error", err)
		}
	}

	// Initialize time

	// Checking the kernel symbol needs to happen after obtaining the capability;
	// otherwise, we get a warning.
	usedClockID := timeutil.CLOCK_BOOTTIME
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
				usedClockID = timeutil.CLOCK_MONOTONIC
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
	err = timeutil.Init(int32(usedClockID))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// elapsed time in nanoseconds since system start
	t.startTime = uint64(timeutil.GetStartTimeNS())
	// time in nanoseconds when the system was booted
	t.bootTime = uint64(timeutil.GetBootTimeNS())

	// Initialize events field types map

	t.eventDecodeTypes = make(map[events.ID][]data.DecodeAs)
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id := eventDefinition.GetID()
		fields := eventDefinition.GetFields()
		for _, field := range fields {
			// Skip returnValue field - it's not part of syscall arguments captured on entry,
			// it's added separately on exit in the eBPF code
			if field.Name == "returnValue" {
				continue
			}
			t.eventDecodeTypes[id] = append(t.eventDecodeTypes[id], field.DecodeAs)
		}
	}

	// Initialize Process Tree (if enabled)

	var processTree *process.ProcessTree
	if t.config.ProcessStore.Source != process.SourceNone {
		// Procfs enrichment is now supported with both CLOCK_BOOTTIME and CLOCK_MONOTONIC.
		// The timeutil.ProcfsStartTimeToEpochNS() function handles the conversion from
		// procfs values (always BOOTTIME) to the BPF clock base (MONOTONIC or BOOTTIME).
		processTree, err = process.NewProcessTree(ctx, t.config.ProcessStore)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize DataStore Registry (after datastores are created)

	t.dataStoreRegistry = datastores.NewRegistry()

	// Register core datastores
	// ProcessTree is optional (may be nil if Source == SourceNone)
	if err := t.dataStoreRegistry.RegisterStore(dsapi.Process, processTree, false); err != nil {
		return errfmt.WrapError(err)
	}

	if err := t.dataStoreRegistry.RegisterStore(dsapi.Container, containerMgr, true); err != nil {
		return errfmt.WrapError(err)
	}

	// DNS cache is optional (may be nil if DNSStore.Enable is false)
	if err := t.dataStoreRegistry.RegisterStore(dsapi.DNS, dnsCache, false); err != nil {
		return errfmt.WrapError(err)
	}

	// Kernel symbols can be hot-reloaded at runtime, so we use an adapter
	// that always fetches the current symbol table
	kernelSymbolAdapter := symbol.NewAdapter(t.getKernelSymbols)
	if err := t.dataStoreRegistry.RegisterStore(dsapi.Symbol, kernelSymbolAdapter, true); err != nil {
		return errfmt.WrapError(err)
	}

	// System information is collected once at startup and is immutable
	systemInfo, err := system.CollectSystemInfo()
	if err != nil {
		return errfmt.WrapError(err)
	}
	// Set Tracee's start time (in nanoseconds since epoch)
	systemInfo.TraceeStartTime = timeutil.NsSinceEpochToTime(t.startTime)
	systemStore := system.New(systemInfo)
	if err := t.dataStoreRegistry.RegisterStore(dsapi.System, systemStore, false); err != nil {
		return errfmt.WrapError(err)
	}

	// Syscall information datastore provides syscall ID <-> name mapping
	syscallStore := syscall.New(events.Core)
	if err := t.dataStoreRegistry.RegisterStore(dsapi.Syscall, syscallStore, true); err != nil {
		return errfmt.WrapError(err)
	}

	if t.registerE2eDatastoresFn != nil {
		if err := t.registerE2eDatastoresFn(t.dataStoreRegistry.Registry()); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize all registered datastores
	// This will call Initialize(ctx) on stores that implement it (e.g., container.Populate())
	if err := t.dataStoreRegistry.InitializeAll(ctx); err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize event derivation logic (after datastores are initialized)
	err = t.initDerivationTable()
	if err != nil {
		return errfmt.Errorf("error initializing event derivation map: %v", err)
	}

	// Register detectors from config (after datastores are registered and initialized)
	if err := t.registerAllDetectors(t.config.DetectorConfig.Detectors); err != nil {
		return errfmt.WrapError(err)
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

	// Initialize eBPF programs and maps extensions phase
	if err := t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseBPFPrograms); err != nil {
		return err
	}

	// Initialize hashes for files

	t.fileHashes, err = digest.NewCache(t.config.Output.CalcHashes, t.contPathResolver)
	if err != nil {
		t.Close()
		return errfmt.WrapError(err)
	}

	// Initialize artifacts directory

	if err := os.MkdirAll(t.config.Artifacts.OutputPath, 0755); err != nil {
		t.Close()
		return errfmt.Errorf("error creating output path: %v", err)
	}

	t.OutDir, err = fileutil.OpenExistingDir(t.config.Artifacts.OutputPath)
	if err != nil {
		t.Close()
		return errfmt.Errorf("error opening out directory: %v", err)
	}

	// Initialize network capture (all needed pcap files)

	t.netCapturePcap, err = pcaps.New(t.config.Artifacts.Net, t.OutDir)
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
			return &events.PipelineEvent{
				Event: &trace.Event{},
			}
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

	// Initialize extensions complete
	return t.extensions.InitExtensionsForPhase(ctx, t, InitPhaseComplete)
}

// initTailCall initializes a given tailcall by updating the BPF map with the program FD.
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

// uninitTailCall removes a given tailcall by deleting its entries from the BPF map.
func (t *Tracee) uninitTailCall(tailCall events.TailCall) error {
	tailCallMapName := tailCall.GetMapName()
	tailCallIndexes := tailCall.GetIndexes()

	// Pick eBPF map by name.
	bpfMap, err := t.bpfModule.GetMap(tailCallMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Remove all indexes for this tailcall
	for _, index := range tailCallIndexes {
		// Workaround: Do not try to remove unsupported syscalls (arm64, e.g.)
		if index >= uint32(events.Unsupported) {
			continue
		}
		// Delete the entry from the BPF map
		err := bpfMap.DeleteKey(unsafe.Pointer(&index))
		if err != nil {
			// Log but don't fail on individual delete errors
			logger.Errorw("Failed to uninit tailcall index",
				"map", tailCallMapName,
				"index", index,
				"error", err)
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

	coreDerivations := derive.Table{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:        shouldSubmit(events.ContainerCreate),
				DeriveFunction: derive.ContainerCreate(t.dataStoreRegistry.GetContainerManager()),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:        shouldSubmit(events.ContainerRemove),
				DeriveFunction: derive.ContainerRemove(t.dataStoreRegistry.GetContainerManager()),
			},
		},
		events.SyscallTableCheck: {
			events.HookedSyscall: {
				Enabled:        shouldSubmit(events.SyscallTableCheck),
				DeriveFunction: derive.DetectHookedSyscall(t.getKernelSymbols()),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:        shouldSubmit(events.HookedSeqOps),
				DeriveFunction: derive.HookedSeqOps(t.getKernelSymbols()),
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
					t.dataStoreRegistry.GetDNSCache(),
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
		events.NetPacketFlowBase: {
			events.NetFlowTCPBegin: {
				Enabled: shouldSubmit(events.NetFlowTCPBegin),
				DeriveFunction: derive.NetFlowTCPBegin(
					t.dataStoreRegistry.GetDNSCache(),
				),
			},
			events.NetFlowTCPEnd: {
				Enabled: shouldSubmit(events.NetFlowTCPEnd),
				DeriveFunction: derive.NetFlowTCPEnd(
					t.dataStoreRegistry.GetDNSCache(),
				),
			},
		},
	}

	// Register core derivations using the registration function
	t.RegisterEventDerivations(coreDerivations)

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

	if t.config.Output.Environment {
		cOptVal = cOptVal | optExecEnv
	}
	if t.config.Output.UserStack {
		cOptVal = cOptVal | optStackAddresses
	}
	if t.config.Artifacts.FileWrite.Capture {
		cOptVal = cOptVal | optCaptureFilesWrite
	}
	if t.config.Artifacts.FileRead.Capture {
		cOptVal = cOptVal | optCaptureFileRead
	}
	if t.config.Artifacts.Module {
		cOptVal = cOptVal | optCaptureModules
	}
	if t.config.Artifacts.Bpf {
		cOptVal = cOptVal | optCaptureBpf
	}
	if t.config.Artifacts.Mem {
		cOptVal = cOptVal | optExtractDynCode
	}
	switch t.cgroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		cOptVal = cOptVal | optCgroupV1
	}
	if t.config.Output.FdPaths {
		cOptVal = cOptVal | optTranslateFDFilePath
	}
	switch t.config.ProcessStore.Source {
	case process.SourceBoth, process.SourceEvents:
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
	for _, id := range t.eventsDependencies.GetEvents() {
		if !events.Core.IsDefined(id) {
			return errfmt.Errorf("event %d is not defined", id)
		}

		depsNode, err := t.eventsDependencies.GetEvent(id)
		if err != nil {
			logger.Warnw("failed to extract required ksymbols from event", "event", events.Core.GetDefinitionByID(id).GetName(), "error", err)
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

		// Add fallback ksym dependencies so they will be available for fallbacks (as they have to be requested upon initialization)
		def := events.Core.GetDefinitionByID(id)
		fallbacks := def.GetDependencies().GetFallbacks()
		for _, fallback := range fallbacks {
			ksyms := fallback.GetKSymbols()
			ksymNames := make([]string, 0, len(ksyms))
			for _, sym := range ksyms {
				ksymNames = append(ksymNames, sym.GetSymbolName())
			}
			t.requiredKsyms = append(t.requiredKsyms, ksymNames...)
		}

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

		// Add fallback kprobe/kretprobe dependencies so they will be available for fallbacks
		// (as they have to be requested upon initialization)
		for _, fallback := range fallbacks {
			depsProbes := fallback.GetProbes()
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
	}

	// Specific cases
	if _, err := t.eventsDependencies.GetEvent(events.HookedSeqOps); err == nil {
		for _, seqName := range derive.NetSeqOps {
			t.requiredKsyms = append(t.requiredKsyms, seqName)
		}
	}
	if _, err := t.eventsDependencies.GetEvent(events.HookedSyscall); err == nil {
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
	if _, err := t.eventsDependencies.GetEvent(events.PrintMemDump); err == nil {
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
func getUnavailbaleKsymbols(ksymbols []events.KSymbol, kernelSymbols *symbol.KernelSymbolTable) []events.KSymbol {
	var unavailableSymbols []events.KSymbol

	for _, ksymbol := range ksymbols {
		_, err := kernelSymbols.GetSymbolByName(ksymbol.GetSymbolName())
		if err != nil {
			// If the symbol is not found, it means it's unavailable.
			unavailableSymbols = append(unavailableSymbols, ksymbol)
			continue
		}
	}
	return unavailableSymbols
}

// validateKallsymsDependencies load all symbols required by events dependencies
// from the kallsyms file to check for missing symbols. If some symbols are
// missing, it will cancel their event with informative error message.
func (t *Tracee) validateKallsymsDependencies() {
	validateNode := func(node *dependencies.EventNode) bool {
		deps := node.GetDependencies()
		missingDepSyms := getUnavailbaleKsymbols(deps.GetKSymbols(), t.getKernelSymbols())
		shouldFailEvent := false
		for _, symDep := range missingDepSyms {
			if symDep.IsRequired() {
				shouldFailEvent = true
				break
			}
		}
		if shouldFailEvent {
			eventNameToCancel := events.Core.GetDefinitionByID(node.GetID()).GetName()
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

	validateEvent := func(eventId events.ID) bool {
		depsNode, err := t.eventsDependencies.GetEvent(eventId)
		if err != nil {
			logger.Errorw("Failed to get dependencies for event", "event", events.Core.GetDefinitionByID(eventId).GetName(), "error", err)
			return false
		}
		return validateNode(depsNode)
	}

	t.eventsDependencies.SubscribeAdd(
		dependencies.EventNodeType,
		func(node interface{}) []dependencies.Action {
			eventNode, ok := node.(*dependencies.EventNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			if !validateNode(eventNode) {
				return []dependencies.Action{dependencies.NewFailNodeAddAction(errors.New("event is missing ksymbols"))}
			}
			return nil
		})

	for _, eventId := range t.eventsDependencies.GetEvents() {
		// Continuously validate the event and mark it as failed if required ksymbols are missing,
		// until all necessary ksymbols become available or the event is removed.
		// This process enables the event to attempt fallbacks as needed, potentially resulting in different ksymbol dependencies each time.
		for !validateEvent(eventId) {
			// Cancel the event, its dependencies and its dependent events
			removed, err := t.eventsDependencies.FailEvent(eventId)
			if err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "missing ksymbols", "error", err)
				break
			}
			if removed {
				break
			}
			// If the event is not removed, it means it has fallbacks, so we need to try the next fallback
		}
	}
}

// setProgramsAutoload configures which eBPF programs are set to autoload based on the selected events.
// When the eBPF module is loaded, only programs marked for autoload will be loaded into the kernel.
// This function ensures that all programs required by the selected events are set to autoload.
// Additionally, it registers dependency watchers to automatically update the autoload status of probes
// when events are added or removed. This approach guarantees that only the necessary programs are loaded,
// supporting kernels where some programs may not be available.
func (t *Tracee) setProgramsAutoload() {
	for _, probeHandle := range t.eventsDependencies.GetProbes() {
		err := t.defaultProbes.Autoload(probeHandle, true)
		if err != nil {
			logger.Debugw("Failed to autoload program", "handle", probeHandle, "error", err)
		}
	}

	// Upon adding a probe, ensure it's autoloaded
	t.eventsDependencies.SubscribeAdd(
		dependencies.ProbeNodeType,
		func(node interface{}) []dependencies.Action {
			probeNode, ok := node.(*dependencies.ProbeNode)
			if !ok {
				logger.Errorw("Got node from type not requested", "type", fmt.Sprintf("%T", node))
				return nil
			}
			err := t.defaultProbes.Autoload(probeNode.GetHandle(), true)
			if err != nil {
				logger.Debugw("Failed to autoload program", "handle", probeNode.GetHandle(), "error", err)
			}
			return nil
		})

	// Upon removing a probe, ensure it's not autoloaded
	t.eventsDependencies.SubscribeRemove(
		dependencies.ProbeNodeType,
		func(node interface{}) []dependencies.Action {
			probeNode, ok := node.(*dependencies.ProbeNode)
			if !ok {
				logger.Errorw("Got node from type not requested", "type", fmt.Sprintf("%T", node))
				return nil
			}
			err := t.defaultProbes.Autoload(probeNode.GetHandle(), false)
			if err != nil {
				logger.Debugw("Failed to autoload program", "handle", probeNode.GetHandle(), "error", err)
			}
			return nil
		})
}

// setMapsAutocreate configures the autocreate flag for all eBPF maps in the module.
// By default, all maps are set to autocreate, which means they will be created automatically
// when the eBPF object is loaded. This function checks each map's type (and its inner map type, if present)
// for kernel support using the provided environment information. If a map or its inner map type is not
// supported by the running kernel, the autocreate flag for that map is set to false, preventing its creation
// and avoiding potential load failures due to unsupported map types.
func (t *Tracee) setMapsAutocreate() {
	iterator := t.bpfModule.Iterator()

	for bpfMap := iterator.NextMap(); bpfMap != nil; bpfMap = iterator.NextMap() {
		if err := validateMapSupport(bpfMap); err != nil {
			if errors.Is(err, ErrUnsupportedMapType) {
				logger.Debugw("Map type is not supported, cancelling autocreate", "map_name", bpfMap.Name(), "reason", err.Error())
				err = bpfMap.SetAutocreate(false)
				if err != nil {
					logger.Warnw("Failed to cancel autocreate of map", "map_name", bpfMap.Name(), "error", err)
				}
			} else {
				logger.Warnw("Failed to check map support", "map_name", bpfMap.Name(), "error", err)
			}
		}
	}
}

// ErrUnsupportedMapType indicates a BPF map type is not supported by the kernel
var ErrUnsupportedMapType = errors.New("unsupported map type")

// validateMapSupport validates if the map and its inner map (if any) are supported.
// It returns an error with a nested ErrUnsupportedMapType if the map is not supported.
// Any other error suggest there was error in the validation itself.
func validateMapSupport(bpfMap *bpf.BPFMap) error {
	// Check main map
	supported, err := bpf.BPFMapTypeIsSupported(bpfMap.Type())
	if err != nil {
		return err
	}
	if !supported {
		return fmt.Errorf("%w: %s", ErrUnsupportedMapType, bpfMap.Type())
	}

	// Check inner map if exists
	innerMap, err := bpfMap.InnerMapInfo()
	if err != nil { // No inner map
		return nil
	}

	supported, err = bpf.BPFMapTypeIsSupported(innerMap.Type)
	if err != nil {
		return err
	}
	if !supported {
		return fmt.Errorf("%w: inner type %s", ErrUnsupportedMapType, innerMap.Type)
	}
	return nil
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
	if pcaps.PcapsEnabled(t.config.Artifacts.Net) {
		bpfNetConfigMap, err := t.bpfModule.GetMap("netconfig_map")
		if err != nil {
			return errfmt.WrapError(err)
		}

		netConfigVal := make([]byte, 8) // u32 capture_options + u32 capture_length
		options := pcaps.GetPcapOptions(t.config.Artifacts.Net)
		binary.LittleEndian.PutUint32(netConfigVal[0:4], uint32(options))
		binary.LittleEndian.PutUint32(netConfigVal[4:8], t.config.Artifacts.Net.CaptureLength)

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
	err = t.dataStoreRegistry.GetContainerManager().PopulateBpfMap(t.bpfModule)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Set filters given by the user to filter file write events
	fileWritePathFilterMap, err := t.bpfModule.GetMap("file_write_path_filter") // u32, u32
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(t.config.Artifacts.FileWrite.PathFilter)); i++ {
		filterFilePathWriteBytes := []byte(t.config.Artifacts.FileWrite.PathFilter[i])
		if err = fileWritePathFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&filterFilePathWriteBytes[0])); err != nil {
			return err
		}
	}

	// Set filters given by the user to filter file read events
	fileReadPathFilterMap, err := t.bpfModule.GetMap("file_read_path_filter") // u32, u32
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(t.config.Artifacts.FileRead.PathFilter)); i++ {
		filterFilePathReadBytes := []byte(t.config.Artifacts.FileRead.PathFilter[i])
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
	captureReadTypeFilterVal := uint32(t.config.Artifacts.FileRead.TypeFilter)
	if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureReadTypeFilterIndex),
		unsafe.Pointer(&captureReadTypeFilterVal)); err != nil {
		return errfmt.WrapError(err)
	}

	// Should match the value of CAPTURE_WRITE_TYPE_FILTER_IDX in eBPF code
	captureWriteTypeFilterIndex := uint32(1)
	captureWriteTypeFilterVal := uint32(t.config.Artifacts.FileWrite.TypeFilter)
	if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureWriteTypeFilterIndex),
		unsafe.Pointer(&captureWriteTypeFilterVal)); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// populateFilterMaps populates the eBPF maps with the given policies
func (t *Tracee) populateFilterMaps(updateProcTree bool) error {
	polCfg, err := t.policyManager.UpdateBPF(
		t.bpfModule,
		t.dataStoreRegistry.GetContainerManager(),
		t.eventDecodeTypes,
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
			err := t.defaultProbes.Attach(probeNode.GetHandle(), t.cgroups, t.getKernelSymbols())
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
				logger.Errorw("Failed to detach probe",
					"probe", probeNode.GetHandle(),
					"error", err)
			}
			return nil
		})

	// Attach probes to their respective eBPF programs or fail probes (and dependent events) if a required probe is missing.
	for _, probeHandle := range t.eventsDependencies.GetProbes() {
		// Calling attachment of probes more than once is a supported behavior, and will do nothing
		// if it has been attached already.
		err := t.defaultProbes.Attach(probeHandle, t.cgroups, t.getKernelSymbols())
		if err != nil {
			// Mark the probe as failed, which will also fail all dependent events as needed.
			// TODO: Support probes loading with fallbacks during runtime.
			//       At this stage, only the probes currently in use are loaded, which prevents successfully transitioning to fallbacks if needed.
			failErr := t.eventsDependencies.FailProbe(probeHandle)
			if failErr != nil {
				logger.Warnw("Failed to fail probe in dependencies manager", "probe", probeHandle, "attach error", err, "fail error", failErr)
			}
		}
	}
	// TODO: Update the eBPF maps according to events state after failure of attachments
	return nil
}

// attachTailCalls initializes selected tailcalls by updating their BPF maps.
func (t *Tracee) attachTailCalls() error {
	// Subscribe to watchers on the dependencies to initialize and/or uninitialize
	// tailcalls upon changes
	t.eventsDependencies.SubscribeAdd(
		dependencies.TailCallNodeType,
		func(node interface{}) []dependencies.Action {
			tailCallNode, ok := node.(*dependencies.TailCallNode)
			if !ok {
				logger.Errorw("Got node from type not requested", "type", fmt.Sprintf("%T", node))
				return nil
			}
			tailCall := tailCallNode.GetTailCall()
			err := t.initTailCall(tailCall)
			if err != nil {
				// Cancel adding this tailcall node if initialization fails
				return []dependencies.Action{dependencies.NewCancelNodeAddAction(err)}
			}
			return nil
		})

	t.eventsDependencies.SubscribeRemove(
		dependencies.TailCallNodeType,
		func(node interface{}) []dependencies.Action {
			tailCallNode, ok := node.(*dependencies.TailCallNode)
			if !ok {
				logger.Errorw("Got node from type not requested", "type", fmt.Sprintf("%T", node))
				return nil
			}
			tailCall := tailCallNode.GetTailCall()
			err := t.uninitTailCall(tailCall)
			if err != nil {
				logger.Errorw("Failed to uninit tailcall",
					"map", tailCall.GetMapName(),
					"program", tailCall.GetProgName(),
					"error", err)
			}
			return nil
		})

	// Initialize all current tailcalls or fail them (and dependent events) if initialization fails.
	for _, tailCallKey := range t.eventsDependencies.GetTailCalls() {
		tailCallNode, err := t.eventsDependencies.GetTailCall(tailCallKey)
		if err != nil {
			logger.Errorw("Failed to get tailcall from dependencies manager", "key", tailCallKey, "error", err)
			continue
		}
		tailCall := tailCallNode.GetTailCall()

		// Initialize this specific tailcall
		err = t.initTailCall(tailCall)
		if err != nil {
			// Mark this specific tailcall as failed, which will also fail all dependent events as needed.
			failErr := t.eventsDependencies.FailTailCall(tailCall)
			if failErr != nil {
				logger.Warnw("Failed to fail tailcall in dependencies manager",
					"tailcall", tailCallKey,
					"init error", err,
					"fail error", failErr)
			}
		}
	}

	return nil
}

// validateProbesCompatibility validates the compatibility of probes and their fallbacks.
// It will subscribe to the dependencies to validate the compatibility of new probes and their fallbacks as well.
func (t *Tracee) validateProbesCompatibility() error {
	// First, check the compatibility of newly added probes.
	// If a probe is incompatible and the event has a fallback, the fallback's compatibility will also be checked.
	// This ensures that only compatible probes (or their fallbacks) are used for event handling.
	t.eventsDependencies.SubscribeAdd(
		dependencies.ProbeNodeType,
		func(node interface{}) []dependencies.Action {
			probeNode, ok := node.(*dependencies.ProbeNode)
			if !ok {
				logger.Errorw("Got node from type not requested")
				return nil
			}
			probeCompatibility, err := t.defaultProbes.IsProbeCompatible(probeNode.GetHandle(), t.config.OSInfo)
			if err != nil {
				logger.Warnw("Failed to check probe compatibility", "error", err)
				return nil
			}
			if !probeCompatibility {
				return []dependencies.Action{dependencies.NewFailNodeAddAction(errors.New("probe is not compatible with the current environment"))}
			}
			return nil
		})

	for _, probeHandle := range t.eventsDependencies.GetProbes() {
		probeCompatibility, err := t.defaultProbes.IsProbeCompatible(probeHandle, t.config.OSInfo)
		if err != nil {
			logger.Errorw("Failed to check probe compatibility", "error", err)
			continue
		}
		if !probeCompatibility {
			logger.Debugw("Probe failed due to incompatible probe", "probe", probeHandle)
			err := t.eventsDependencies.FailProbe(probeHandle)
			if err != nil {
				logger.Warnw("Failed to fail incompatible probe", "probe", probeHandle, "error", err)
			}
		}
	}

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

	t.defaultProbes, err = probes.NewDefaultProbeGroup(t.bpfModule, t.netEnabled(), false, t.config.BPFObjPath)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return t.validateProbesCompatibility()
}

func (t *Tracee) initBPF() error {
	var err error

	// Load the eBPF object into kernel

	t.setProgramsAutoload()
	t.setMapsAutocreate()

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

	t.controlPlane = controlplane.NewController(
		t.bpfModule,
		t.dataStoreRegistry.GetContainerManager(),
		t.config.EnrichmentEnabled,
		t.dataStoreRegistry.GetProcessTree(),
		t.dataTypeDecoder,
		t.config.Buffers.Kernel.ControlPlane,
	)
	if err := t.controlPlane.Init(); err != nil {
		return errfmt.WrapError(err)
	}

	// returned PoliciesConfig is not used here, therefore it's discarded
	_, err = t.policyManager.UpdateBPF(t.bpfModule, t.dataStoreRegistry.GetContainerManager(), t.eventDecodeTypes, false, true)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize perf buffers and needed channels

	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	if t.config.Buffers.Kernel.Events < 1 {
		return errfmt.Errorf("invalid perf buffer size: %d", t.config.Buffers.Kernel.Events)
	}
	t.eventsPerfMap, err = t.bpfModule.InitPerfBuf(
		"events",
		t.eventsChannel,
		t.lostEvChannel,
		t.config.Buffers.Kernel.Events,
	)
	if err != nil {
		return errfmt.Errorf("error initializing events perf map: %v", err)
	}

	if t.config.Buffers.Kernel.Artifacts > 0 {
		t.fileCapturesChannel = make(chan []byte, 1000)
		t.lostCapturesChannel = make(chan uint64)
		t.fileWrPerfMap, err = t.bpfModule.InitPerfBuf(
			"file_writes",
			t.fileCapturesChannel,
			t.lostCapturesChannel,
			t.config.Buffers.Kernel.Artifacts,
		)
		if err != nil {
			return errfmt.Errorf("error initializing file_writes perf map: %v", err)
		}
	}

	if pcaps.PcapsEnabled(t.config.Artifacts.Net) {
		t.netCapChannel = make(chan []byte, 1000)
		t.lostNetCapChannel = make(chan uint64)
		t.netCapPerfMap, err = t.bpfModule.InitPerfBuf(
			"net_cap_events",
			t.netCapChannel,
			t.lostNetCapChannel,
			t.config.Buffers.Kernel.Events,
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
		t.config.Buffers.Kernel.Events,
	)
	if err != nil {
		return errfmt.Errorf("error initializing logs perf map: %v", err)
	}

	// Attach eBPF programs to selected event's probes

	// TODO: Solve race window between ProcessTreeFilters initialization through procfs and the
	// attachment of the probes that update the filters from the eBPF side. Maybe perform another
	// iteration on procfs to fill in any missing data.

	err = t.attachProbes()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize tailcalls for selected events
	err = t.attachTailCalls()

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

	// Run Extensions
	if err := t.extensions.RunExtensions(ctx, t); err != nil {
		return errfmt.Errorf("error running extensions: %v", err)
	}

	// Set up on-demand BPF metrics collection (METRICS build only)

	if version.MetricsBuild() {
		if err := t.initializeBPFEventsStatsMap(); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Main event loop (polling events perf buffer)

	t.eventsPerfMap.Poll(pollTimeout)

	pipelineReady := make(chan struct{}, 1)
	go t.processLostEvents() // termination signaled by closing t.done
	go t.handleEvents(ctx, pipelineReady)

	// Parallel perf buffer with file writes events

	if t.config.Buffers.Kernel.Artifacts > 0 {
		t.fileWrPerfMap.Poll(pollTimeout)
		go t.handleFileCaptures(ctx)
	}

	// Network capture perf buffer (similar to regular pipeline)

	if pcaps.PcapsEnabled(t.config.Artifacts.Net) {
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

	// Stop perf buffers (close them when no more events are being processed)

	t.eventsPerfMap.Stop()
	err := t.controlPlane.Stop()
	if err != nil {
		return errfmt.Errorf("error stopping control plane: %v", err)
	}
	if t.config.Buffers.Kernel.Artifacts > 0 {
		t.fileWrPerfMap.Stop()
	}
	if pcaps.PcapsEnabled(t.config.Artifacts.Net) {
		t.netCapPerfMap.Stop()
	}
	t.bpfLogsPerfMap.Stop()

	// TODO: move logic below somewhere else (related to file writes)

	// record index of written files
	if t.config.Artifacts.FileWrite.Capture {
		err := updateArtifactsMapFile(t.OutDir, "written_files", t.writtenFiles, t.config.Artifacts.FileWrite)
		if err != nil {
			return err
		}
	}

	// record index of read files
	if t.config.Artifacts.FileRead.Capture {
		err := updateArtifactsMapFile(t.OutDir, "read_files", t.readFiles, t.config.Artifacts.FileRead)
		if err != nil {
			return err
		}
	}

	t.Close() // close Tracee

	return nil
}

func updateArtifactsMapFile(fileDir *os.File, filePath string, artifactsFiles map[string]string, cfg config.FileArtifactsConfig) error {
	f, err := fileutil.OpenAt(fileDir, filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errfmt.Errorf("error logging captured files")
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	for fileName, filePath := range artifactsFiles {
		artifactsFiltered := false
		// TODO: We need a method to decide if the artifacts was filtered by FD or type.
		for _, filterPrefix := range cfg.PathFilter {
			if !strings.HasPrefix(filePath, filterPrefix) {
				artifactsFiltered = true
				break
			}
		}
		if artifactsFiltered {
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

	// Shutdown all datastores with a reasonable timeout.
	// 5 seconds allows graceful cleanup without blocking Tracee termination indefinitely.
	if t.dataStoreRegistry != nil {
		shutdownCtx, cancel := gocontext.WithTimeout(gocontext.Background(), 5*time.Second)
		defer cancel()
		if err := t.dataStoreRegistry.ShutdownAll(shutdownCtx); err != nil {
			logger.Errorw("Failed to shutdown datastores", "error", err)
		}
	}

	// Close all the perf buffers
	if t.eventsPerfMap != nil {
		t.eventsPerfMap.Close()
	}
	if t.fileWrPerfMap != nil {
		t.fileWrPerfMap.Close()
	}
	if t.netCapPerfMap != nil {
		t.netCapPerfMap.Close()
	}
	if t.bpfLogsPerfMap != nil {
		t.bpfLogsPerfMap.Close()
	}

	// Close the control plane
	if t.controlPlane != nil {
		err := t.controlPlane.Close()
		if err != nil {
			logger.Errorw("failed to close control plane when closing tracee", "err", err)
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
	if t.dataStoreRegistry != nil && t.dataStoreRegistry.GetContainerManager() != nil {
		err := t.dataStoreRegistry.GetContainerManager().Close()
		if err != nil {
			logger.Errorw("failed to clean containers module when closing tracee", "err", err)
		}
	}
	if err := t.cgroups.Destroy(); err != nil {
		logger.Errorw("Cgroups destroy", "error", err)
	}

	// Close Extensions
	if err := t.extensions.CloseExtensions(t); err != nil {
		logger.Errorw("failed to close extensions", "error", err)
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
	f, err := fileutil.OpenAt(t.OutDir, fileName, os.O_RDONLY, 0)
	if err != nil {
		return "", errfmt.WrapError(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()
	return digest.ComputeFileHash(f)
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

	for _, tr := range t.eventsDependencies.GetEvents() {
		definition := events.Core.GetDefinitionByID(tr)
		if definition.NotValid() {
			continue
		}
		eventName := definition.GetName()
		eventNode, err := t.eventsDependencies.GetEvent(tr)
		if err != nil {
			continue
		}

		for _, depProbes := range eventNode.GetDependencies().GetProbes() {
			currProbe := t.defaultProbes.GetProbeByHandle(depProbes.GetHandle())
			name := ""

			// Only log all other probe types except TraceProbe
			p, ok := currProbe.(*probes.TraceProbe)
			if !ok {
				// Log all other probe types using interface assertion
				if p, ok := currProbe.(interface{ GetProgramName() string }); ok {
					log(eventName, p.GetProgramName())
				}
				continue
			}
			// Perform the rest of the logic for TraceProbe
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

			log(eventName, p.GetProgramName())
			name = p.GetEventName()

			selfLoadedPrograms[name]++
		}
	}

	return selfLoadedPrograms
}

// invokeInitEvents emits Tracee events, called Initialization Events, that are generated from the
// userland process itself, and not from the kernel. These events usually serve as informational
// events for the signatures engine/logic.
func (t *Tracee) invokeInitEvents(ctx gocontext.Context, out chan *events.PipelineEvent) {
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
		out <- events.NewPipelineEvent(&traceeDataEvent)
		_ = t.stats.EventCount.Increment()
	}

	matchedPolicies = policiesMatch(events.InitNamespaces)
	if matchedPolicies > 0 {
		systemInfoEvent := events.InitNamespacesEvent()
		setMatchedPolicies(&systemInfoEvent, matchedPolicies)
		out <- events.NewPipelineEvent(&systemInfoEvent)
		_ = t.stats.EventCount.Increment()
	}

	// Initial existing containers events (1 event per container)

	matchedPolicies = policiesMatch(events.ExistingContainer)
	if matchedPolicies > 0 {
		existingContainerEvents := events.ExistingContainersEvents(t.dataStoreRegistry.GetContainerManager(), t.config.EnrichmentEnabled)
		for i := range existingContainerEvents {
			event := &(existingContainerEvents[i])
			setMatchedPolicies(event, matchedPolicies)
			out <- events.NewPipelineEvent(event)
			_ = t.stats.EventCount.Increment()
		}
	}

	// Ftrace hook event

	matchedPolicies = policiesMatch(events.FtraceHook)
	if matchedPolicies > 0 {
		ftraceBaseEvent := events.GetFtraceBaseEvent()
		setMatchedPolicies(ftraceBaseEvent, matchedPolicies)

		// TODO: Ideally, this should be inside the goroutine and be computed before each run,
		// as in the future tracee events may be changed in run time.
		// Currently, moving it inside the goroutine leads to a circular importing due to
		// eventsState (which is used inside the goroutine).
		// eventsState is planned to be removed, and this call should move inside the routine
		// once that happens.
		selfLoadedFtraceProgs := t.getSelfLoadedPrograms(true)

		go events.FtraceHookEvent(ctx, t.stats.EventCount, out, ftraceBaseEvent, selfLoadedFtraceProgs)
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
	return pcaps.PcapsEnabled(t.config.Artifacts.Net)
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

// Subscribe returns a stream subscribed to selected policies
func (t *Tracee) Subscribe(stream config.Stream) (*streams.Stream, error) {
	policyMask := policy.PolicyAll
	eventMap := map[int32]struct{}{}

	if len(stream.Filters.Policies) > 0 {
		policyMask = 0

		for _, policyName := range stream.Filters.Policies {
			p, err := t.policyManager.LookupByName(policyName)
			if err != nil {
				return nil, err
			}
			bitwise.SetBit(&policyMask, uint(p.ID))
		}
	}

	if len(stream.Filters.Events) > 0 {
		for _, eventName := range stream.Filters.Events {
			id, found := v1beta1.EventId_value[eventName]
			if !found {
				return nil, errfmt.Errorf("error event not found: %s", eventName)
			}

			eventMap[id] = struct{}{}
		}
	}

	return t.subscribe(policyMask, eventMap, stream.Buffer), nil
}

func (t *Tracee) subscribe(policyMask uint64, eventMap map[int32]struct{}, bufferConfig config.StreamBuffer) *streams.Stream {
	// To keep old behavior in case of streams created from GRPC server
	if bufferConfig.Size <= 0 {
		bufferConfig.Size = t.config.Buffers.Pipeline
	}

	return t.streamsManager.Subscribe(policyMask, eventMap, bufferConfig)
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

	// If this is a signature event, also load the signature to start its goroutine
	eventDef := events.Core.GetDefinitionByID(id)
	if eventDef.IsSignature() {
		// Find the corresponding signature in available signatures
		if t.sigEngine != nil {
			for _, sig := range t.config.EngineConfig.AvailableSignatures {
				metadata, err := sig.GetMetadata()
				if err != nil {
					logger.Errorw("Failed to get signature metadata", "error", err)
					continue
				}

				// Check if this signature matches the event name
				if metadata.EventName == eventName {
					_, err := t.sigEngine.LoadSignature(sig)
					if err != nil {
						logger.Errorw("Failed to load signature", "signature", metadata.Name, "error", err)
						return errfmt.Errorf("failed to load signature %s: %v", metadata.Name, err)
					}
					logger.Debugw("Loaded signature", "signature", metadata.Name, "event", eventName)
					break
				}
			}
		}
	}

	return nil
}

func (t *Tracee) DisableEvent(eventName string) error {
	id, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	t.policyManager.DisableEvent(id)

	// If this is a signature event, also unload the signature to stop its goroutine
	eventDef := events.Core.GetDefinitionByID(id)
	if eventDef.IsSignature() {
		// Find the corresponding signature in available signatures
		if t.sigEngine != nil {
			for _, sig := range t.config.EngineConfig.AvailableSignatures {
				metadata, err := sig.GetMetadata()
				if err != nil {
					logger.Errorw("Failed to get signature metadata", "error", err)
					continue
				}

				// Check if this signature matches the event name
				if metadata.EventName == eventName {
					err := t.sigEngine.UnloadSignature(metadata.ID)
					if err != nil {
						logger.Errorw("Failed to unload signature", "signature", metadata.Name, "error", err)
						return errfmt.Errorf("failed to unload signature %s: %v", metadata.Name, err)
					}
					logger.Debugw("Unloaded signature", "signature", metadata.Name, "event", eventName)
					break
				}
			}
		}
	}

	return nil
}

// registerAllDetectors registers detectors with the engine.
// Event IDs must be pre-registered in events.Core before calling this function.
func (t *Tracee) registerAllDetectors(detectorList []detection.EventDetector) error {
	logger.Debugw("Registering detectors", "count", len(detectorList))

	// Build detector parameters
	params := detection.DetectorParams{
		Logger:     logger.Current(),
		DataStores: t.dataStoreRegistry.Registry(),
		Config:     detection.NewEmptyDetectorConfig(), // Empty config for now
	}

	// Register all detectors
	for _, detector := range detectorList {
		definition := detector.GetDefinition()

		if err := t.detectorEngine.RegisterDetector(detector, params); err != nil {
			logger.Errorw("Failed to register detector",
				"detector", definition.ID,
				"error", err)
			// Continue with other detectors - don't fail startup for one detector
			continue
		}
	}

	logger.Debugw("Detector registration complete",
		"total", len(detectorList),
		"registered", t.detectorEngine.GetDetectorCount())

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

// RegisterEventDerivations allows additional event derivations to be registered
func (t *Tracee) RegisterEventDerivations(eventDerivations derive.Table) {
	if t.eventDerivations == nil {
		t.eventDerivations = make(derive.Table)
	}
	// Merge event derivations into existing ones
	for deriveFrom, derivations := range eventDerivations {
		if t.eventDerivations[deriveFrom] == nil {
			t.eventDerivations[deriveFrom] = make(map[events.ID]struct {
				DeriveFunction derive.DeriveFunction
				Enabled        func() bool
			})
		}
		for deriveTo, derivation := range derivations {
			t.eventDerivations[deriveFrom][deriveTo] = derivation
		}
	}
}

func (t *Tracee) MetricsEnabled() bool {
	return t.config.MetricsEnabled
}
