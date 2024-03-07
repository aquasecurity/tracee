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
	"github.com/aquasecurity/libbpfgo/helpers"

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
	eventsParamTypes map[events.ID][]bufferdecoder.ArgType
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
	kernelSymbols *helpers.KernelSymbolTable
	// eBPF
	bpfModule *bpf.Module
	probes    *probes.ProbeGroup
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
}

func (t *Tracee) Stats() *metrics.Stats {
	return &t.stats
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

	// Create Tracee

	t := &Tracee{
		config:         cfg,
		done:           make(chan struct{}),
		writtenFiles:   make(map[string]string),
		readFiles:      make(map[string]string),
		capturedFiles:  make(map[string]int64),
		streamsManager: streams.NewStreamsManager(),
	}

	// Initialize capabilities rings soon

	err = capabilities.Initialize(t.config.Capabilities.BypassCaps)
	if err != nil {
		return t, errfmt.WrapError(err)
	}
	caps := capabilities.GetInstance()

	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		return t, errfmt.WrapError(err)
	}

	policy.Manager().EnableRules(policies)

	// Update capabilities rings with all events dependencies

	err = policy.Manager().UpdateCapabilitiesRings(policies)
	if err != nil {
		return t, errfmt.WrapError(err)
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
func (t *Tracee) Init(ctx gocontext.Context, initialPolicies policy.PoliciesBuilder) error {
	var err error

	// Init kernel symbols map

	err = capabilities.GetInstance().Specific(
		func() error {
			// TODO: turn kernelSymbols a singleton
			t.kernelSymbols, err = helpers.NewKernelSymbolTable()
			return err
		},
		cap.SYSLOG,
	)
	if err != nil {
		return errfmt.WrapError(err)
	}

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

	// Initialize event derivation logic

	// TODO: initDerivationTable should be rethinked and moved to policy package.
	// But it's not possible to do it now because derive imports policy (circular dependency).
	err = t.initDerivationTable(initialPolicies.(policy.Policies))
	if err != nil {
		return errfmt.Errorf("error initializing event derivation map: %v", err)
	}

	// Initialize events parameter types map
	t.eventsParamTypes = make(map[events.ID][]bufferdecoder.ArgType)
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id := eventDefinition.GetID()
		params := eventDefinition.GetParams()
		for _, param := range params {
			t.eventsParamTypes[id] = append(t.eventsParamTypes[id], bufferdecoder.GetParamType(param.Type))
		}
	}

	// Initialize eBPF programs and maps

	err = capabilities.GetInstance().EBPF(
		func() error {
			return t.initBPF(initialPolicies.EventsFlags())
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

	// Initialize times

	t.startTime = uint64(utils.GetStartTimeNS())
	t.bootTime = uint64(utils.GetBootTimeNS())

	// Decoupled initialization of Policies eBPF

	//
	// TODO: HERE IS THE RIGHT PLACE TO CALL
	//
	// policy.Manager().ApplyPolicies(initialPolicies)

	// disable events w/ missing ksyms dependencies
	policy.SetKsyms(t.kernelSymbols)
	err = policy.Manager().ValidateKallsymsDependencies(initialPolicies)
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = capabilities.GetInstance().EBPF(
		func() error {
			evtsFlags := initialPolicies.EventsFlags()

			// Update the kallsyms eBPF map with all symbols from the kallsyms file

			err = t.UpdateKallsyms(evtsFlags)
			if err != nil {
				return err
			}

			// Populate the eBPF maps with the current policies

			polCfg, err := policy.Manager().PopulateBPF(
				initialPolicies,
				t.bpfModule,
				t.containers,
				t.eventsParamTypes,
			)
			if err != nil {
				return errfmt.WrapError(err)
			}

			// Create a new Config with updated policies and update its BPF map

			cfg := t.newConfig(polCfg, initialPolicies.Version())
			if err := cfg.UpdateBPF(t.bpfModule); err != nil {
				return errfmt.WrapError(err)
			}

			// Initialize tail call dependencies

			tailCalls := events.Core.GetTailCalls(evtsFlags)
			for _, tailCall := range tailCalls {
				err := t.initTailCall(tailCall)
				if err != nil {
					return errfmt.Errorf("failed to initialize tail call: %v", err)
				}
			}

			// Attach eBPF programs to selected event's probes

			err = policy.Manager().AttachProbes(initialPolicies, t.probes, t.cgroups)
			if err != nil {
				return err
			}

			// UpdateProcessTreeBPF must be called after AttachProbes.
			// For more information, see UpdateProcessTreeBPF documentation.

			err = policy.Manager().PopulateProcessTreeBPF(initialPolicies)
			if err != nil {
				return errfmt.WrapError(err)
			}

			return nil
		},
	)
	if err != nil {
		logger.Errorw("error initializing Policies eBPF", "error", err)
	}

	return nil
}

type InitValues struct {
	Kallsyms bool
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

	once := &sync.Once{}

	// Pick all indexes (event, or syscall, IDs) the BPF program should be related to.
	for _, index := range tailCallIndexes {
		// Special treatment for indexes of syscall events.
		if events.Core.GetDefinitionByID(events.ID(index)).IsSyscall() {
			// Optimization: enable enter/exit probes only if at least one syscall is enabled.
			once.Do(func() {
				err := t.probes.Attach(probes.SyscallEnter__Internal)
				if err != nil {
					logger.Errorw("error attaching to syscall enter", "error", err)
				}
				err = t.probes.Attach(probes.SyscallExit__Internal)
				if err != nil {
					logger.Errorw("error attaching to syscall enter", "error", err)
				}
			})
			// Workaround: Do not map eBPF program to unsupported syscalls (arm64, e.g.)
			if index >= uint32(events.Unsupported) {
				continue
			}
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
func (t *Tracee) initDerivationTable(ps policy.Policies) error {
	shouldSubmit := func(id events.ID) func() bool {
		return func() bool { return ps.EventsFlags().Get(id).ShouldSubmit() }
	}
	symbolsCollisions := derive.SymbolsCollision(t.contSymbolsLoader, ps)

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
					ps,
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
	optProcessInfo
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
// the given computed policies config and version.
func (t *Tracee) newConfig(cfg *policy.PoliciesConfig, version uint16) *Config {
	return &Config{
		TraceePid:       uint32(os.Getpid()),
		Options:         t.getOptionsConfig(),
		CgroupV1Hid:     uint32(t.cgroups.GetDefaultCgroupHierarchyID()),
		PoliciesVersion: version,
		PoliciesConfig:  *cfg,
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

	return nil
}

func (t *Tracee) initBPF(evtsFlags events.EventsFlags) error {
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

	t.probes, err = probes.NewDefaultProbeGroup(t.bpfModule, t.netEnabled(evtsFlags), t.kernelSymbols)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Load the eBPF object into kernel

	err = t.bpfModule.BPFLoadObject()
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
		t.bpfModule,
		t.containers,
		t.config.NoContainersEnrich,
		t.processTree,
	)
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

	return errfmt.WrapError(err)
}

const pollTimeout int = 300

// Run starts the trace. it will run until ctx is cancelled
func (t *Tracee) Run(ctx gocontext.Context) error {
	// Some events need initialization before the perf buffers are polled

	// NOTE: GetLast is being used here to get the last policy version.
	// If the events below are able to be defined for upcoming or previous versions
	// and expected to be triggered by them, then the entire related logic must be changed.
	// The main place to look is the policy package.
	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		return errfmt.WrapError(err)
	}

	evtsFlags := policies.EventsFlags()

	// HookedSeqOps event
	// check if event is defined even if it's not enabled (emit/submit)
	if _, ok := evtsFlags.GetOk(events.HookedSeqOps); ok {
		t.triggerSeqOpsIntegrityCheck(trace.Event{})
	}

	// HookedSyscall event
	if evtsFlags.Get(events.HookedSyscall).ShouldSubmit() {
		go t.hookedSyscallTableRoutine(ctx)
	}

	// PrintMemDump event
	// check if event is defined even if it's not enabled (emit/submit)
	if _, ok := policies.EventsFlags().GetOk(events.PrintMemDump); ok {
		errs := t.triggerMemDump(policies, trace.Event{})
		for _, err := range errs {
			logger.Warnw("Memory dump", "error", err)
		}
	}

	// HiddenKernelModule event
	if evtsFlags.Get(events.HiddenKernelModule).ShouldEmit() {
		go t.lkmSeekerRoutine(ctx)
	}

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
	if t.probes != nil {
		err := t.probes.DetachAll()
		if err != nil {
			logger.Errorw("failed to detach probes when closing tracee", "err", err)
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
func (t *Tracee) getSelfLoadedPrograms(evtsFlags events.EventsFlags, kprobesOnly bool) map[string]int {
	selfLoadedPrograms := map[string]int{} // map k: symbol name, v: number of hooks

	log := func(event string, program string) {
		logger.Debugw("self loaded program", "event", event, "program", program)
	}

	type probeMapKey struct {
		programName string
		probeType   probes.ProbeType
	}
	// We need to count how many ftrace based hooks will be placed on each symbol.
	// evtsFlags may contain duplicate events due to dependencies.
	// To get the real count, we consider the program name and the prob type.
	// For example:
	// event flags may contain the following entries:
	// eventName: do_init_module, programName: trace_do_init_module, probtype: 0, definitionID: 778
	// eventName: do_init_module, programName: trace_ret_do_init_module, probtype: 1, definitionID: 778
	// eventName: do_init_module, programName: trace_do_init_module, probtype: 0, definitionID: 760
	// eventName: do_init_module, programName: trace_ret_do_init_module, probtype: 1, definitionID: 760
	// Even though there are 4 entries, we can see that only 2 hooks are going to be placed in practice.
	// The symbol is do_init_module: kprobe with the program trace_do_init_module, kretprobe with the program trace_ret_do_init_module
	uniqueHooksMap := map[probeMapKey]struct{}{}

	for tr := range evtsFlags.GetAll() {
		if !events.Core.IsDefined(tr) {
			continue
		}

		definition := events.Core.GetDefinitionByID(tr)

		for _, depProbes := range definition.GetDependencies().GetProbes() {
			currProbe := t.probes.GetProbeByHandle(depProbes.GetHandle())
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
				key := probeMapKey{
					programName: p.GetProgramName(),
					probeType:   p.GetProbeType(),
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
	var emit uint64

	setMatchedPolicies := func(event *trace.Event, matchedPolicies uint64, pols policy.Policies) {
		event.PoliciesVersion = pols.Version()
		event.MatchedPoliciesKernel = matchedPolicies
		event.MatchedPoliciesUser = matchedPolicies
		event.MatchedPolicies = pols.MatchedNames(matchedPolicies)
	}

	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		logger.Errorw("failed to get policies", "error", err)
		return
	}

	evtsFlags := policies.EventsFlags()

	// Initial namespace events

	emit = evtsFlags.Get(events.InitNamespaces).GetEmit()
	if emit > 0 {
		systemInfoEvent := events.InitNamespacesEvent()
		setMatchedPolicies(&systemInfoEvent, emit, policies)
		out <- &systemInfoEvent
		_ = t.stats.EventCount.Increment()
	}

	// Initial existing containers events (1 event per container)

	emit = evtsFlags.Get(events.ExistingContainer).GetEmit()
	if emit > 0 {
		existingContainerEvents := events.ExistingContainersEvents(t.containers, t.config.NoContainersEnrich)
		for i := range existingContainerEvents {
			event := &(existingContainerEvents[i])
			setMatchedPolicies(event, emit, policies)
			out <- event
			_ = t.stats.EventCount.Increment()
		}
	}

	// Ftrace hook event

	emit = evtsFlags.Get(events.FtraceHook).GetEmit()
	if emit > 0 {
		ftraceBaseEvent := events.GetFtraceBaseEvent()
		setMatchedPolicies(ftraceBaseEvent, emit, policies)
		logger.Debugw("started ftraceHook goroutine")

		// TODO: Ideally, this should be inside the goroutine and be computed before each run,
		// as in the future tracee events may be changed in run time.
		// Currently, moving it inside the goroutine leads to a circular importing due to
		// eventsState (which is used inside the goroutine).
		// eventsState is planned to be removed, and this call should move inside the routine
		// once that happens.
		selfLoadedFtraceProgs := t.getSelfLoadedPrograms(evtsFlags, true)

		go events.FtraceHookEvent(t.stats.EventCount, out, ftraceBaseEvent, selfLoadedFtraceProgs)
	}
}

// netEnabled returns true if any base network event is to be traced
func (t *Tracee) netEnabled(evtsFlags events.EventsFlags) bool {
	for k := range evtsFlags.GetAll() {
		if k >= events.NetPacketBase && k <= events.MaxNetID {
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
func (t *Tracee) triggerMemDump(policies policy.Policies, event trace.Event) []error {
	errs := []error{}

	// TODO: consider to iterate over given policies when policies are changed
	for p := range policies.Map() {
		printMemDumpFilters := p.ArgFilter().GetEventFilters(events.PrintMemDump)
		if len(printMemDumpFilters) == 0 {
			errs = append(errs, errfmt.Errorf("policy %d: no address or symbols were provided to print_mem_dump event. "+
				"please provide it via -e print_mem_dump.args.address=<hex address>"+
				", -e print_mem_dump.args.symbol_name=<owner>:<symbol> or "+
				"-e print_mem_dump.args.symbol_name=<symbol> if specifying a system owned symbol", p.GetID()))

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
				errs = append(errs, errfmt.Errorf("policy %d: invalid length provided to print_mem_dump event: %v", p.GetID(), err))

				continue
			}
		}

		addressFilter, ok := printMemDumpFilters["address"].(*filters.StringFilter)
		if addressFilter != nil && ok {
			for _, field := range addressFilter.Equal() {
				address, err := strconv.ParseUint(field, 16, 64)
				if err != nil {
					errs[p.GetID()] = errfmt.Errorf("policy %d: invalid address provided to print_mem_dump event: %v", p.GetID(), err)

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
					errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - more than one ':' provided", p.GetID(), field))

					continue
				}
				symbol, err := t.kernelSymbols.GetSymbolByOwnerAndName(owner, name)
				if err != nil {
					if owner != "system" {
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s - %v", p.GetID(), field, err))

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
						errs = append(errs, errfmt.Errorf("policy %d: invalid symbols provided to print_mem_dump event: %s", p.GetID(), attemptedSymbols))

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

	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		return nil, err
	}

	for _, policyName := range policyNames {
		p, err := policies.LookupByName(policyName)
		if err != nil {
			return nil, err
		}
		utils.SetBit(&policyMask, uint(p.GetID()))
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
	id, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	policy.Manager().EnableEvent(id)

	return nil
}

func (t *Tracee) DisableEvent(eventName string) error {
	id, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		return errfmt.Errorf("error event not found: %s", eventName)
	}

	policy.Manager().DisableEvent(id)

	return nil
}

// EnableRule enables a rule in the specified policies
func (t *Tracee) EnableRule(policyNames []string, ruleId string) error {
	eventID, found := events.Core.GetDefinitionIDByName(ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		return err
	}

	for _, policyName := range policyNames {
		p, err := policies.LookupByName(policyName)
		if err != nil {
			return err
		}

		policy.Manager().EnableRule(p.GetID(), eventID)
	}

	return nil
}

// DisableRule disables a rule in the specified policies
func (t *Tracee) DisableRule(policyNames []string, ruleId string) error {
	eventID, found := events.Core.GetDefinitionIDByName(ruleId)
	if !found {
		return errfmt.Errorf("error rule not found: %s", ruleId)
	}

	policies, err := policy.Manager().GetCurrent()
	if err != nil {
		return err
	}

	for _, policyName := range policyNames {
		p, err := policies.LookupByName(policyName)
		if err != nil {
			return err
		}

		policy.Manager().DisableRule(p.GetID(), eventID)
	}

	return nil
}
