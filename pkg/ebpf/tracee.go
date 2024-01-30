package ebpf

import (
	gocontext "context"
	"encoding/binary"
	"fmt"
	"os"
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
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/events/sorting"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/filehash"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
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
	stats     metrics.Stats
	sigEngine *engine.Engine
	// Events
	eventsSorter     *sorting.EventsChronologicalSorter
	eventsPool       *sync.Pool
	eventsParamTypes map[int][]bufferdecoder.ArgType
	eventProcessor   map[int][]func(evt *trace.Event) error
	eventDerivations derive.Table
	eventSignatures  map[int]bool
	// Artifacts
	fileHashes     *filehash.Cache
	capturedFiles  map[string]int64
	writtenFiles   map[string]string
	netCapturePcap *pcaps.Pcaps
	// Internal Data
	readFiles   map[string]string
	pidsInMntns bucketscache.BucketsCache // first n PIDs in each mountns
	// eBPF
	probes *extensions.ProbesPerExtension
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
	policyManager *policyManager
}

func (t *Tracee) Stats() *metrics.Stats {
	return &t.stats
}

func (t *Tracee) Engine() *engine.Engine {
	return t.sigEngine
}

// handleEventsDependencies handles all events dependencies recursively.
func (t *Tracee) handleEventsDependencies(givenEvtId int) {
	giventEvtDef := extensions.Definitions.GetDefinitionByID("core", givenEvtId)
	givenEvtDeps := giventEvtDef.GetDependencies().GetIDs()
	givenEvtState := extensions.States.GetOrCreate("core", int(givenEvtId))

	for _, depEvtID := range givenEvtDeps {
		depEvtState := extensions.States.GetOrCreate("core", int(depEvtID))

		// Submit all dependencies of a given event.
		depEvtState.OrSubmitFrom(givenEvtState)

		// Mark all signature event dependencies as signature events.
		if extensions.Definitions.GetDefinitionByID("core", givenEvtId).IsSignature() {
			t.eventSignatures[depEvtID] = true
		}

		// Handle dependencies recursively.
		t.handleEventsDependencies(depEvtID)
	}
}

// New creates a new Tracee instance based on a given valid Config. It is expected that it won't
// cause external system side effects (reads, writes, etc).
func New(cfg config.Config) (*Tracee, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, errfmt.Errorf("validation error: %v", err)
	}

	policyManager := newPolicyManager()

	// Create Tracee

	t := &Tracee{
		config:          cfg,
		done:            make(chan struct{}),
		writtenFiles:    make(map[string]string),
		readFiles:       make(map[string]string),
		capturedFiles:   make(map[string]int64),
		eventSignatures: make(map[int]bool),
		streamsManager:  streams.NewStreamsManager(),
		policyManager:   policyManager,
	}

	// Initialize capabilities rings soon

	err = capabilities.Initialize(t.config.Capabilities.BypassCaps)
	if err != nil {
		return t, errfmt.WrapError(err)
	}
	caps := capabilities.GetInstance()

	// Initialize events state with mandatory events

	extensions.States.GetOrCreate("core", int(extensions.SchedProcessFork))
	extensions.States.GetOrCreate("core", int(extensions.SchedProcessExec))
	extensions.States.GetOrCreate("core", int(extensions.SchedProcessExit))

	// Control Plane Events

	extensions.States.GetOrCreate("core", int(extensions.SignalCgroupMkdir)).SetSubmitAll()
	extensions.States.GetOrCreate("core", int(extensions.SignalCgroupRmdir)).SetSubmitAll()

	// Control Plane Process Tree Events

	pipeEvts := func() {
		extensions.States.GetOrCreate("core", int(extensions.SchedProcessFork)).SetSubmitAll()
		extensions.States.GetOrCreate("core", int(extensions.SchedProcessExec)).SetSubmitAll()
		extensions.States.GetOrCreate("core", int(extensions.SchedProcessExit)).SetSubmitAll()
	}
	signalEvts := func() {
		extensions.States.GetOrCreate("core", int(extensions.SignalSchedProcessFork)).SetSubmitAll()
		extensions.States.GetOrCreate("core", int(extensions.SignalSchedProcessExec)).SetSubmitAll()
		extensions.States.GetOrCreate("core", int(extensions.SignalSchedProcessExit)).SetSubmitAll()
	}

	// DNS Cache events

	if t.config.DNSCacheConfig.Enable {
		extensions.States.GetOrCreate("core", int(extensions.NetPacketDNS)).SetSubmitAll()
	}

	switch t.config.ProcTree.Source {
	case proctree.SourceBoth:
		pipeEvts()
		signalEvts()
	case proctree.SourceSignals:
		signalEvts()
	case proctree.SourceEvents:
		pipeEvts()
	}

	// Pseudo events added by capture (if enabled by the user)

	switch {
	case cfg.Capture.Exec:
		extensions.States.GetOrCreate("core", int(extensions.CaptureExec)).SetSubmitAll()
	case cfg.Capture.FileWrite.Capture:
		extensions.States.GetOrCreate("core", int(extensions.CaptureFileWrite)).SetSubmitAll()
	case cfg.Capture.FileRead.Capture:
		extensions.States.GetOrCreate("core", int(extensions.CaptureFileRead)).SetSubmitAll()
	case cfg.Capture.Module:
		extensions.States.GetOrCreate("core", int(extensions.CaptureModule)).SetSubmitAll()
	case cfg.Capture.Mem:
		extensions.States.GetOrCreate("core", int(extensions.CaptureMem)).SetSubmitAll()
	case cfg.Capture.Bpf:
		extensions.States.GetOrCreate("core", int(extensions.CaptureBpf)).SetSubmitAll()
	case pcaps.PcapsEnabled(cfg.Capture.Net):
		extensions.States.GetOrCreate("core", int(extensions.CaptureNetPacket)).SetSubmitAll()
	}

	// Events chosen by the user

	for pol := range t.config.Policies.Map() {
		for evtID := range pol.EventsToTrace {
			state := extensions.States.GetOrCreate("core", int(evtID))
			state.SetEmitForPolicy(pol.ID)
			state.SetSubmitForPolicy(pol.ID)
			policyManager.EnableRule(pol.ID, evtID)
		}
	}

	// Handle all essential events dependencies

	for _, evtID := range extensions.States.GetEventIDs("core") {
		t.handleEventsDependencies(int(evtID))
	}

	// Update capabilities rings with all events dependencies

	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := int(id)
		if !extensions.Definitions.IsDefined("core", evtID) {
			return t, errfmt.Errorf("event %d is not defined", evtID)
		}
		def := extensions.Definitions.GetDefinitionByID("core", evtID)
		capsDep := def.GetDependencies().GetCapabilities()
		err = caps.BaseRingAdd(capsDep.GetBase()...)
		if err != nil {
			return t, errfmt.WrapError(err)
		}
		err = caps.BaseRingAdd(capsDep.GetEBPF()...)
		if err != nil {
			return t, errfmt.WrapError(err)
		}
	}

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
// performing external system operations to initialize them. NOTE: any
// initialization logic, especially one that causes side effects, should go
// here and not New().
func (t *Tracee) Init(ctx gocontext.Context) error {
	var err error

	// Init kernel symbols map (done by global initialization)
	// Disable events with missing ksyms dependencies
	extensions.ValidateKsymsDepsAndCancelUnavailableStates()

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

	// Initialize Process Tree (if enabled)

	if t.config.ProcTree.Source != proctree.SourceNone {
		t.processTree, err = proctree.NewProcessTree(ctx, t.config.ProcTree)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Initialize cgroups filesystems

	err = cgroup.CGroups.Init()
	if err != nil {
		logger.Errorw("Initializing cgroups", "error", err)
	}

	// Initialize containers enrichment logic

	t.containers, err = containers.New(
		t.config.NoContainersEnrich,
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

	// Initialize event derivation logic

	err = t.initDerivationTable()
	if err != nil {
		return errfmt.Errorf("error initializing event derivation map: %v", err)
	}

	// Initialize events parameter types map

	t.eventsParamTypes = make(map[int][]bufferdecoder.ArgType)
	for _, definition := range extensions.Definitions.GetDefinitions("core") {
		id := definition.GetID()
		params := definition.GetParams()
		for _, param := range params {
			t.eventsParamTypes[id] = append(t.eventsParamTypes[id], bufferdecoder.GetParamType(param.Type))
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

	stackAddressesMap, err := extensions.Modules.Get("core").GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return errfmt.Errorf("error getting access to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = stackAddressesMap

	// Get reference to fd arg path map
	fdArgPathMap, err := extensions.Modules.Get("core").GetMap("fd_arg_path_map")
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

	// Initialize times

	t.startTime = uint64(utils.GetStartTimeNS())
	t.bootTime = uint64(utils.GetBootTimeNS())

	return nil
}

// initDerivationTable initializes tracee's events.DerivationTable. For each
// event, represented through its ID, we declare to which other events it can be
// derived and the corresponding function to derive into that Event.
func (t *Tracee) initDerivationTable() error {
	shouldSubmit := func(id int) func() bool {
		return func() bool {
			state, ok := extensions.States.GetOk("core", int(id))
			if !ok {
				return false
			}
			return state.AnyEnabled()
		}
	}

	t.eventDerivations = derive.Table{
		extensions.CgroupMkdir: {
			extensions.ContainerCreate: {
				Enabled:        shouldSubmit(extensions.ContainerCreate),
				DeriveFunction: derive.ContainerCreate(t.containers),
			},
		},
		extensions.CgroupRmdir: {
			extensions.ContainerRemove: {
				Enabled:        shouldSubmit(extensions.ContainerRemove),
				DeriveFunction: derive.ContainerRemove(t.containers),
			},
		},
		extensions.SyscallTableCheck: {
			extensions.HookedSyscall: {
				Enabled:        shouldSubmit(extensions.SyscallTableCheck),
				DeriveFunction: derive.DetectHookedSyscall(),
			},
		},
		extensions.PrintNetSeqOps: {
			extensions.HookedSeqOps: {
				Enabled:        shouldSubmit(extensions.HookedSeqOps),
				DeriveFunction: derive.HookedSeqOps(),
			},
		},
		extensions.HiddenKernelModuleSeeker: {
			extensions.HiddenKernelModule: {
				Enabled:        shouldSubmit(extensions.HiddenKernelModuleSeeker),
				DeriveFunction: derive.HiddenKernelModule(),
			},
		},
		extensions.SharedObjectLoaded: {
			extensions.SymbolsLoaded: {
				Enabled: shouldSubmit(extensions.SymbolsLoaded),
				DeriveFunction: derive.SymbolsLoaded(
					t.contSymbolsLoader,
					t.config.Policies,
				),
			},
			extensions.SymbolsCollision: {
				Enabled: shouldSubmit(extensions.SymbolsCollision),
				DeriveFunction: derive.SymbolsCollision(
					t.contSymbolsLoader,
					t.config.Policies,
				),
			},
		},
		extensions.SchedProcessExec: {
			extensions.SymbolsCollision: {
				Enabled: shouldSubmit(extensions.SymbolsCollision),
				DeriveFunction: derive.SymbolsCollision(
					t.contSymbolsLoader,
					t.config.Policies,
				),
			},
		},
		extensions.SecuritySocketConnect: {
			extensions.NetTCPConnect: {
				Enabled: shouldSubmit(extensions.NetTCPConnect),
				DeriveFunction: derive.NetTCPConnect(
					t.dnsCache,
				),
			},
		},
		//
		// Network Packet Derivations
		//
		extensions.NetPacketIPBase: {
			extensions.NetPacketIPv4: {
				Enabled:        shouldSubmit(extensions.NetPacketIPv4),
				DeriveFunction: derive.NetPacketIPv4(),
			},
			extensions.NetPacketIPv6: {
				Enabled:        shouldSubmit(extensions.NetPacketIPv6),
				DeriveFunction: derive.NetPacketIPv6(),
			},
		},
		extensions.NetPacketTCPBase: {
			extensions.NetPacketTCP: {
				Enabled:        shouldSubmit(extensions.NetPacketTCP),
				DeriveFunction: derive.NetPacketTCP(),
			},
		},
		extensions.NetPacketUDPBase: {
			extensions.NetPacketUDP: {
				Enabled:        shouldSubmit(extensions.NetPacketUDP),
				DeriveFunction: derive.NetPacketUDP(),
			},
		},
		extensions.NetPacketICMPBase: {
			extensions.NetPacketICMP: {
				Enabled:        shouldSubmit(extensions.NetPacketICMP),
				DeriveFunction: derive.NetPacketICMP(),
			},
		},
		extensions.NetPacketICMPv6Base: {
			extensions.NetPacketICMPv6: {
				Enabled:        shouldSubmit(extensions.NetPacketICMPv6),
				DeriveFunction: derive.NetPacketICMPv6(),
			},
		},
		extensions.NetPacketDNSBase: {
			extensions.NetPacketDNS: {
				Enabled:        shouldSubmit(extensions.NetPacketDNS),
				DeriveFunction: derive.NetPacketDNS(),
			},
			extensions.NetPacketDNSRequest: {
				Enabled:        shouldSubmit(extensions.NetPacketDNSRequest),
				DeriveFunction: derive.NetPacketDNSRequest(),
			},
			extensions.NetPacketDNSResponse: {
				Enabled:        shouldSubmit(extensions.NetPacketDNSResponse),
				DeriveFunction: derive.NetPacketDNSResponse(),
			},
		},
		extensions.NetPacketHTTPBase: {
			extensions.NetPacketHTTP: {
				Enabled:        shouldSubmit(extensions.NetPacketHTTP),
				DeriveFunction: derive.NetPacketHTTP(),
			},
			extensions.NetPacketHTTPRequest: {
				Enabled:        shouldSubmit(extensions.NetPacketHTTPRequest),
				DeriveFunction: derive.NetPacketHTTPRequest(),
			},
			extensions.NetPacketHTTPResponse: {
				Enabled:        shouldSubmit(extensions.NetPacketHTTPResponse),
				DeriveFunction: derive.NetPacketHTTPResponse(),
			},
		},
		//
		// Network Flow Derivations
		//
		extensions.NetPacketFlow: {
			extensions.NetFlowTCPBegin: {
				Enabled: shouldSubmit(extensions.NetFlowTCPBegin),
				DeriveFunction: derive.NetFlowTCPBegin(
					t.dnsCache,
				),
			},
			extensions.NetFlowTCPEnd: {
				Enabled: shouldSubmit(extensions.NetFlowTCPEnd),
				DeriveFunction: derive.NetFlowTCPEnd(
					t.dnsCache,
				),
			},
		},
	}

	return nil
}

// RegisterEventDerivation registers an event derivation handler for tracee to use in the event pipeline
func (t *Tracee) RegisterEventDerivation(deriveFrom int, deriveTo int, deriveCondition func() bool, deriveLogic derive.DeriveFunction) error {
	if t.eventDerivations == nil {
		return errfmt.Errorf("tracee not initialized yet")
	}

	return t.eventDerivations.Register(deriveFrom, deriveTo, deriveCondition, deriveLogic)
}

// Config options should match eBPF code:

const (
	optExecEnv uint32 = 1 << iota
	optCaptureFilesWrite
	optExtractDynCode
	optStackAddresses
	optCaptureModules
	optCgroupV1
	optProcessInfo
	optTranslateFDFilePath
	optCaptureBpf
	optCaptureFileRead
	optForkProcTree
)

// getOptionsConfig returns a uint32 representing the current Tracee config.
func (t *Tracee) getOptionsConfig() uint32 {
	var cOptVal uint32

	switch {
	case t.config.Output.ExecEnv:
		cOptVal = cOptVal | optExecEnv
	case t.config.Output.StackAddresses:
		cOptVal = cOptVal | optStackAddresses
	case t.config.Capture.FileWrite.Capture:
		cOptVal = cOptVal | optCaptureFilesWrite
	case t.config.Capture.FileRead.Capture:
		cOptVal = cOptVal | optCaptureFileRead
	case t.config.Capture.Module:
		cOptVal = cOptVal | optCaptureModules
	case t.config.Capture.Bpf:
		cOptVal = cOptVal | optCaptureBpf
	case t.config.Capture.Mem:
		cOptVal = cOptVal | optExtractDynCode
	case t.config.Output.ParseArgumentsFDs:
		cOptVal = cOptVal | optTranslateFDFilePath
	}

	switch cgroup.CGroups.GetDefaultCgroup().(type) {
	case *cgroup.CgroupV1:
		cOptVal = cOptVal | optCgroupV1
	}

	switch t.config.ProcTree.Source {
	case proctree.SourceBoth, proctree.SourceEvents:
		cOptVal = cOptVal | optForkProcTree
	}

	return cOptVal
}

// newConfig returns a new Config instance based on the current Tracee state and
// the given policies config and version.
func (t *Tracee) newConfig(cfg *policy.PoliciesConfig, version uint16) *Config {
	return &Config{
		TraceePid:       uint32(os.Getpid()),
		Options:         t.getOptionsConfig(),
		CgroupV1Hid:     uint32(cgroup.CGroups.GetDefaultCgroupHierarchyID()),
		PoliciesVersion: version,
		PoliciesConfig:  *cfg,
	}
}

func (t *Tracee) populateBPFMaps() error {
	// Prepare 32bit to 64bit syscall number mapping
	sys32to64BPFMap, err := extensions.Modules.Get("core").GetMap("sys_32_to_64_map")
	if err != nil {
		return errfmt.WrapError(err)
	}
	for _, eventDefinition := range extensions.Definitions.GetDefinitions("core") {
		id32BitU32 := uint32(eventDefinition.GetID32Bit()) // ID32Bit is int32
		idU32 := uint32(eventDefinition.GetID())           // ID is int32
		err := sys32to64BPFMap.Update(unsafe.Pointer(&id32BitU32), unsafe.Pointer(&idU32))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Update the kallsyms eBPF map with all symbols from the kallsyms file.
	err = extensions.UpdateKallsyms()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize kconfig ebpf map with values from the kernel config file.
	// TODO: remove this from libbpf and try to rely in libbpf only for kconfig vars.
	bpfKConfigMap, err := extensions.Modules.Get("core").GetMap("kconfig_map")
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
		bpfNetConfigMap, err := extensions.Modules.Get("core").GetMap("netconfig_map")
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
	err = t.populateFilterMaps(t.config.Policies, false)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Populate containers map with existing containers
	err = t.containers.PopulateBpfMap()
	if err != nil {
		return errfmt.WrapError(err)
	}

	coreBPFModule := extensions.Modules.Get("core")

	// Set filters given by the user to filter file write events
	fileWritePathFilterMap, err := coreBPFModule.GetMap("file_write_path_filter")
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
	fileReadPathFilterMap, err := coreBPFModule.GetMap("file_read_path_filter")
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
	fileTypeFilterMap, err := coreBPFModule.GetMap("file_type_filter")
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
	tailCalls := extensions.Definitions.GetTailCalls("core")
	for _, tailCall := range tailCalls {
		err := tailCall.Init()
		if err != nil {
			return errfmt.Errorf("failed to initialize tail call: %v", err)
		}
	}

	return nil
}

// populateFilterMaps populates the eBPF maps with the given policies
func (t *Tracee) populateFilterMaps(newPolicies *policy.Policies, updateProcTree bool) error {
	polCfg, err := newPolicies.UpdateBPF(
		t.containers,
		t.eventsParamTypes,
		true,
		updateProcTree,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Create new config with updated policies and update eBPF map

	cfg := t.newConfig(polCfg, newPolicies.Version())
	if err := cfg.UpdateBPF(); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}

// attachProbes attaches selected events probes to their respective eBPF progs
func (t *Tracee) attachProbes() error {
	var err error

	// Cancel event and its dependencies recursively.
	var cancelEventFromEventStateRecursively func(evtID int)

	cancelEventFromEventStateRecursively = func(evtID int) {
		extensions.States.Delete("core", int(evtID))
		evtDef := extensions.Definitions.GetDefinitionByID("core", evtID)
		for _, evtDeps := range evtDef.GetDependencies().GetIDs() {
			cancelEventFromEventStateRecursively(evtDeps)
		}
	}

	// Get probe dependencies for a given event ID
	getProbeDeps := func(id int) []extensions.ProbeDep {
		def := extensions.Definitions.GetDefinitionByID("core", id)
		return def.GetDependencies().GetProbes()
	}

	// Get the list of probes to attach for each event being traced.
	probesToEvents := make(map[extensions.ProbeDep][]int)
	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := int(id)
		if !extensions.Definitions.IsDefined("core", evtID) {
			continue
		}
		for _, probeDep := range getProbeDeps(evtID) {
			probesToEvents[probeDep] = append(probesToEvents[probeDep], evtID)
		}
	}

	// Attach probes to their eBPF programs.
	for probeDependency, evtID := range probesToEvents {
		pr, ok := extensions.Probes.GetOk("core", probeDependency.GetHandle())
		if !ok {
			return errfmt.Errorf("probe %v is not defined", probeDependency.GetHandle())
		}
		err = pr.Attach(cgroup.CGroups)
		if err != nil {
			for _, evtID := range evtID {
				evtName := extensions.Definitions.GetDefinitionByID("core", evtID).GetName()
				if probeDependency.IsRequired() {
					logger.Errorw(
						"Cancelling event and its dependencies because of missing probe",
						"missing probe", probeDependency.GetHandle(), "event", evtName,
					)
					// Cancel events if a required probe is missing.
					cancelEventFromEventStateRecursively(evtID)
				} else {
					logger.Debugw(
						"Failed to attach non-required probe for event",
						"event", evtName, "probe", probeDependency.GetHandle(),
						"error", err,
					)
				}
			}
		}
	}

	return nil
}

func (t *Tracee) initBPF() error {
	// Execute code with higher privileges: ring1 (required)

	newModuleArgs := bpf.NewModuleArgs{
		KConfigFilePath: t.config.KernelConfig.GetKernelConfigFilePath(),
		BTFObjPath:      t.config.BTFObjPath,
		BPFObjBuff:      t.config.BPFObjBytes,
	}

	// Open the eBPF object file (create a new module)

	bpfModule, err := bpf.NewModuleFromBufferArgs(newModuleArgs)
	if err != nil {
		return errfmt.WrapError(err)
	}
	extensions.Modules.Set("core", bpfModule)

	// Load the eBPF object into kernel

	err = bpfModule.BPFLoadObject()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Populate eBPF maps with initial data

	err = t.populateBPFMaps()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize Control Plane

	t.controlPlane, err = controlplane.NewController(
		t.containers,
		t.config.NoContainersEnrich,
		t.processTree,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Attach eBPF programs to selected event's probes

	err = t.attachProbes()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Update all ProcessTreeFilters after probes are attached: reduce the
	// possible race window between the bpf programs updating the maps and
	// userland reading procfs and also dealing with same maps.

	// returned PoliciesConfig is not used here, therefore it's discarded
	_, err = t.config.Policies.UpdateBPF(
		t.containers,
		t.eventsParamTypes,
		false,
		true,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize perf buffers and needed channels

	coreBPFModule := extensions.Modules.Get("core")

	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	if t.config.PerfBufferSize < 1 {
		return errfmt.Errorf("invalid perf buffer size: %d", t.config.PerfBufferSize)
	}
	t.eventsPerfMap, err = coreBPFModule.InitPerfBuf(
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
		t.fileWrPerfMap, err = coreBPFModule.InitPerfBuf(
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
		t.netCapPerfMap, err = coreBPFModule.InitPerfBuf(
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
	t.bpfLogsPerfMap, err = coreBPFModule.InitPerfBuf(
		"logs",
		t.bpfLogsChannel,
		t.lostBPFLogChannel,
		t.config.PerfBufferSize,
	)
	if err != nil {
		return errfmt.Errorf("error initializing logs perf map: %v", err)
	}

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
	// Unsubscribe all streams connected if tracee is done.
	if t.streamsManager != nil {
		t.streamsManager.Close()
	}
	// Close the control plane.
	if t.controlPlane != nil {
		err := t.controlPlane.Stop()
		if err != nil {
			logger.Errorw("failed to stop control plane when closing tracee", "err", err)
		}
	}
	// Close all probes..
	if t.probes != nil {
		err := extensions.Probes.DetachAll("core")
		if err != nil {
			logger.Errorw("failed to detach probes when closing tracee", "err", err)
		}
	}
	// Close all modules for the core extension.
	extensions.Modules.Get("core").Close()
	// Close container module.
	if t.containers != nil {
		err := t.containers.Close()
		if err != nil {
			logger.Errorw("failed to clean containers module when closing tracee", "err", err)
		}
	}
	// Close the cgroups module.
	if err := cgroup.CGroups.Destroy(); err != nil {
		logger.Errorw("Cgroups destroy", "error", err)
	}
	// Set 'running' to false and close 'done' channel.
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

	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := int(id)
		if !extensions.Definitions.IsDefined("core", evtID) {
			continue
		}

		definition := extensions.Definitions.GetDefinitionByID("core", evtID)

		for _, depProbes := range definition.GetDependencies().GetProbes() {
			currProbe, ok := extensions.Probes.GetOk("core", depProbes.GetHandle())
			if !ok {
				continue
			}
			name := ""
			switch p := currProbe.(type) {
			case *extensions.TraceProbe:
				// Only k[ret]probes may use ftrace
				if kprobesOnly {
					switch p.GetProbeType() {
					case extensions.KProbe, extensions.KretProbe:
					default:
						continue
					}
				}
				log(definition.GetName(), p.GetProgramName())
				name = p.GetEventName()
			case *extensions.Uprobe:
				log(definition.GetName(), p.GetProgramName())
				continue
			case *extensions.CgroupProbe:
				log(definition.GetName(), p.GetProgramName())
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
	var emit uint64

	setMatchedPolicies := func(event *trace.Event, matchedPolicies uint64, pols *policy.Policies) {
		event.PoliciesVersion = pols.Version()
		event.MatchedPoliciesKernel = matchedPolicies
		event.MatchedPoliciesUser = matchedPolicies
		event.MatchedPolicies = pols.MatchedNames(matchedPolicies)
	}

	// Initial namespace events

	state, ok := extensions.States.GetOk("core", int(extensions.InitNamespaces))
	if ok && state.AnyEmitEnabled() {
		systemInfoEvent := events.InitNamespacesEvent()
		setMatchedPolicies(&systemInfoEvent, emit, t.config.Policies)
		out <- &systemInfoEvent
		_ = t.stats.EventCount.Increment()
	}

	// Initial existing containers events (1 event per container)

	state, ok = extensions.States.GetOk("core", int(extensions.ExistingContainer))
	if ok && state.AnyEmitEnabled() {
		for _, e := range events.ExistingContainersEvents(t.containers, t.config.NoContainersEnrich) {
			setMatchedPolicies(&e, emit, t.config.Policies)
			out <- &e
			_ = t.stats.EventCount.Increment()
		}
	}

	// Ftrace hook event

	state, ok = extensions.States.GetOk("core", int(extensions.FtraceHook))
	if ok && state.AnyEmitEnabled() {
		ftraceBaseEvent := events.GetFtraceBaseEvent()
		setMatchedPolicies(ftraceBaseEvent, emit, t.config.Policies)
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
	for _, id := range extensions.States.GetEventIDs("core") {
		evtID := int(id)
		if evtID >= extensions.NetPacketBase && evtID <= extensions.MaxNetID {
			return true
		}
	}

	// if called before capture meta-events are set to be traced:
	return pcaps.PcapsEnabled(t.config.Capture.Net)
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

// SubscribeAll returns a stream subscribed to all policies
func (t *Tracee) SubscribeAll() *streams.Stream {
	return t.subscribe(policy.AllPoliciesOn)
}

// Subscribe returns a stream subscribed to selected policies
func (t *Tracee) Subscribe(policyNames []string) (*streams.Stream, error) {
	var policyMask uint64

	for _, policyName := range policyNames {
		p, err := t.config.Policies.LookupByName(policyName)
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
	return t.streamsManager.Subscribe(policyMask, 10000)
}

// Unsubscribe unsubscribes stream
func (t *Tracee) Unsubscribe(s *streams.Stream) {
	t.streamsManager.Unsubscribe(s)
}

func (t *Tracee) EnableEvent(eventName string) error {
	id, found := extensions.Definitions.GetDefinitionIDByName("core", eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	t.policyManager.EnableEvent(id)

	return nil
}

func (t *Tracee) DisableEvent(eventName string) error {
	id, found := extensions.Definitions.GetDefinitionIDByName("core", eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	t.policyManager.DisableEvent(id)

	return nil
}

// EnableRule enables a rule in the specified policies
func (t *Tracee) EnableRule(policyNames []string, ruleId string) error {
	eventID, found := extensions.Definitions.GetDefinitionIDByName("core", ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	for _, policyName := range policyNames {
		p, err := t.config.Policies.LookupByName(policyName)
		if err != nil {
			return err
		}

		t.policyManager.EnableRule(p.ID, eventID)
	}

	return nil
}

// DisableRule disables a rule in the specified policies
func (t *Tracee) DisableRule(policyNames []string, ruleId string) error {
	eventID, found := extensions.Definitions.GetDefinitionIDByName("core", ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	for _, policyName := range policyNames {
		p, err := t.config.Policies.LookupByName(policyName)
		if err != nil {
			return err
		}

		t.policyManager.DisableRule(p.ID, eventID)
	}

	return nil
}
