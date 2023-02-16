package ebpf

import (
	gocontext "context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/ebpf/initialization"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/events/sorting"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/pcaps"
	"github.com/aquasecurity/tracee/pkg/rules/engine"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/proc"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

const (
	pkgName          = "tracee"
	maxMemDumpLength = 127
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	FilterScopes       *FilterScopes
	Capture            *CaptureConfig
	Capabilities       *CapabilitiesConfig
	Output             *OutputConfig
	Cache              queue.CacheConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	maxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath         string
	BPFObjPath         string
	BPFObjBytes        []byte
	KernelConfig       *helpers.KernelConfig
	ChanEvents         chan trace.Event
	OSInfo             *helpers.OSInfo
	Sockets            runtime.Sockets
	ContainersEnrich   bool
	EngineConfig       engine.Config
}

type CaptureConfig struct {
	OutputPath      string
	FileWrite       bool
	Module          bool
	FilterFileWrite []string
	Exec            bool
	Mem             bool
	Net             pcaps.Config
}

type CapabilitiesConfig struct {
	BypassCaps bool
	AddCaps    []string
	DropCaps   []string
}

type OutputConfig struct {
	StackAddresses    bool
	ExecEnv           bool
	RelativeTime      bool
	ExecHash          bool
	ParseArguments    bool
	ParseArgumentsFDs bool
	EventsSorting     bool
}

// InitValues determines if to initialize values that might be needed by eBPF programs
type InitValues struct {
	kallsyms bool
}

// Validate does static validation of the configuration
func (tc Config) Validate() error {
	for filterScope := range tc.FilterScopes.Map() {
		if filterScope == nil || filterScope.EventsToTrace == nil {
			return fmt.Errorf("FilterScope or EventsToTrace is nil")
		}

		for e := range filterScope.EventsToTrace {
			_, exists := events.Definitions.GetSafe(e)
			if !exists {
				return fmt.Errorf("invalid event [%d] to trace in filter scope [%d]", e, filterScope.ID)
			}
		}
	}
	if (tc.PerfBufferSize & (tc.PerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (tc.BlobPerfBufferSize & (tc.BlobPerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if len(tc.Capture.FilterFileWrite) > 3 {
		return fmt.Errorf("too many file-write filters given")
	}
	for _, filter := range tc.Capture.FilterFileWrite {
		if len(filter) > 50 {
			return fmt.Errorf("the length of a path filter is limited to 50 characters: %s", filter)
		}
	}

	if tc.BPFObjBytes == nil {
		return errors.New("nil bpf object in memory")
	}

	if tc.ChanEvents == nil {
		return errors.New("nil events channel")
	}

	return nil
}

type fileExecInfo struct {
	LastCtime int64
	Hash      string
}

type eventConfig struct {
	submit uint64 // event that should be submitted to userspace (by scopes bitmap)
	emit   uint64 // event that should be emitted to the user (by scopes bitmap)
}

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config            Config
	probes            probes.Probes
	events            map[events.ID]eventConfig
	bpfModule         *bpf.Module
	eventsPerfMap     *bpf.PerfBuffer
	fileWrPerfMap     *bpf.PerfBuffer
	netCapPerfMap     *bpf.PerfBuffer
	bpfLogsPerfMap    *bpf.PerfBuffer
	eventsChannel     chan []byte
	fileWrChannel     chan []byte
	netCapChannel     chan []byte
	bpfLogsChannel    chan []byte
	lostEvChannel     chan uint64
	lostWrChannel     chan uint64
	lostNetCapChannel chan uint64
	lostBPFLogChannel chan uint64
	bootTime          uint64
	startTime         uint64
	stats             metrics.Stats
	capturedFiles     map[string]int64
	fileHashes        *lru.Cache
	writtenFiles      map[string]string
	pidsInMntns       bucketscache.BucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
	StackAddressesMap *bpf.BPFMap
	FDArgPathMap      *bpf.BPFMap
	netCapturePcap    *pcaps.Pcaps
	containers        *containers.Containers
	eventsSorter      *sorting.EventsChronologicalSorter
	eventProcessor    map[events.ID][]func(evt *trace.Event) error
	eventDerivations  derive.Table
	kernelSymbols     helpers.KernelSymbolTable
	triggerContexts   trigger.Context
	running           bool
	outDir            *os.File // All file operations to output dir should be through the utils package file operations (like utils.OpenAt) using this directory file.
	cgroups           *cgroup.Cgroups
}

func (t *Tracee) Stats() *metrics.Stats {
	return &t.stats
}

// GetEssentialEventsList sets the default events used by tracee
func GetEssentialEventsList() map[events.ID]eventConfig {
	// Set essential events
	return map[events.ID]eventConfig{
		events.SchedProcessExec: {},
		events.SchedProcessExit: {},
		events.SchedProcessFork: {},
		events.CgroupMkdir:      {submit: 0xFFFFFFFFFFFFFFFF},
		events.CgroupRmdir:      {submit: 0xFFFFFFFFFFFFFFFF},
	}
}

// GetCaptureEventsList sets events used to capture data
func GetCaptureEventsList(cfg Config) map[events.ID]eventConfig {
	captureEvents := make(map[events.ID]eventConfig)

	// All capture events should be placed, at least for now, to
	// all matched scopes, or else the event won't be set to
	// matched scope in eBPF and should_submit() won't submit
	// the capture event to userland.

	if cfg.Capture.Exec {
		captureEvents[events.CaptureExec] = eventConfig{
			submit: 0xFFFFFFFFFFFFFFFF,
		}
	}
	if cfg.Capture.FileWrite {
		captureEvents[events.CaptureFileWrite] = eventConfig{
			submit: 0xFFFFFFFFFFFFFFFF,
		}
	}
	if cfg.Capture.Module {
		captureEvents[events.CaptureModule] = eventConfig{
			submit: 0xFFFFFFFFFFFFFFFF,
		}
	}
	if cfg.Capture.Mem {
		captureEvents[events.CaptureMem] = eventConfig{
			submit: 0xFFFFFFFFFFFFFFFF,
		}
	}
	if pcaps.PcapsEnabled(cfg.Capture.Net) {
		captureEvents[events.CaptureNetPacket] = eventConfig{
			submit: 0xFFFFFFFFFFFFFFFF,
		}
	}

	return captureEvents
}

func (t *Tracee) handleEventsDependencies(eventId events.ID, submitMap uint64) {
	definition := events.Definitions.Get(eventId)
	eDependencies := definition.Dependencies
	for _, dependentEvent := range eDependencies.Events {
		ec, ok := t.events[dependentEvent.EventID]
		if !ok {
			ec = eventConfig{}
			t.handleEventsDependencies(dependentEvent.EventID, submitMap)
		}
		ec.submit |= submitMap
		t.events[dependentEvent.EventID] = ec
	}
}

// New creates a new Tracee instance based on a given valid Config
// It is expected that New will not cause external system side effects (reads, writes, etc.)
func New(cfg Config) (*Tracee, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	// Create Tracee
	t := &Tracee{
		config:        cfg,
		writtenFiles:  make(map[string]string),
		capturedFiles: make(map[string]int64),
		events:        GetEssentialEventsList(),
	}

	// Initialize capabilities rings soon
	err = capabilities.Initialize(t.config.Capabilities.BypassCaps)
	if err != nil {
		return t, err
	}
	caps := capabilities.GetInstance()

	// Pseudo events added by capture
	for eventID, eCfg := range GetCaptureEventsList(cfg) {
		t.events[eventID] = eCfg
	}

	// Events chosen by the user
	for filterScope := range t.config.FilterScopes.Map() {
		for e := range filterScope.EventsToTrace {
			var submit, emit uint64
			if _, ok := t.events[e]; ok {
				submit = t.events[e].submit
				emit = t.events[e].emit
			}
			utils.SetBit(&submit, uint(filterScope.ID))
			utils.SetBit(&emit, uint(filterScope.ID))
			t.events[e] = eventConfig{submit: submit, emit: emit}
		}
	}

	// Handles all essential events dependencies
	for id, evt := range t.events {
		t.handleEventsDependencies(id, evt.submit)
	}

	// Add Required (by enabled events) capabilities to its ring

	for id := range t.events {
		evt, ok := events.Definitions.GetSafe(id)
		if !ok {
			return t, fmt.Errorf("could not get event")
		}
		for _, capArray := range evt.Dependencies.Capabilities {
			caps.Require(capArray)
		}
	}

	// Add/Drop Required (by the user) capabilities to/from its ring

	capsToAdd, err := capabilities.ReqByString(t.config.Capabilities.AddCaps...)
	if err != nil {
		return t, err
	}
	err = caps.Require(capsToAdd...)
	if err != nil {
		return t, err
	}

	capsToDrop, err := capabilities.ReqByString(t.config.Capabilities.DropCaps...)
	if err != nil {
		return t, err
	}
	err = caps.Unrequire(capsToDrop...)
	if err != nil {
		return t, err
	}

	// Register default event processors
	t.registerEventProcessors()

	t.triggerContexts = trigger.NewContext()

	return t, nil
}

// Init initialize tracee instance and it's various subsystems, potentially
// performing external system operations to initialize them. NOTE: any
// initialization logic, especially one that causes side effects, should go
// here and not New().
func (t *Tracee) Init() error {

	// Initialize needed values

	initReq, err := t.generateInitValues()
	if err != nil {
		return fmt.Errorf("failed to generate required init values: %s", err)
	}

	// Init kernel symbols map

	if initReq.kallsyms {
		err = t.NewKernelSymbols()
		if err != nil {
			return err
		}
	}

	// Canceling events missing kernel symbols
	t.validateKallsymsDependencies()

	// Initialize cgroups filesystems

	t.cgroups, err = cgroup.NewCgroups()
	if err != nil {
		return err
	}

	// Initialize containers enrichment logic

	t.containers, err = containers.New(
		t.cgroups,
		t.config.Sockets,
		"containers_map",
	)
	if err != nil {
		return fmt.Errorf("error initializing containers: %w", err)
	}

	if err := t.containers.Populate(); err != nil {
		return fmt.Errorf("error initializing containers: %w", err)
	}

	// Initialize event derivation logic

	err = t.initDerivationTable()
	if err != nil {
		return fmt.Errorf("error initializing event derivation map: %w", err)
	}

	// Initialize eBPF programs and maps

	err = t.initBPF()
	if err != nil {
		t.Close()
		return err
	}

	// Initialize hashes for files

	t.fileHashes, err = lru.New(1024)
	if err != nil {
		t.Close()
		return err
	}

	// Initialize buckets cache
	if t.config.maxPidsCache == 0 {
		t.config.maxPidsCache = 5 // default value for config.maxPidsCache
	}
	t.pidsInMntns.Init(t.config.maxPidsCache)

	var mntNSProcs map[int]int
	err = capabilities.GetInstance().Requested(func() error {
		mntNSProcs, err = proc.GetMountNSFirstProcesses()
		return err
	},
		cap.DAC_READ_SEARCH,
		cap.SYS_PTRACE,
	)
	if err == nil {
		for mountNS, pid := range mntNSProcs {
			t.pidsInMntns.AddBucketItem(uint32(mountNS), uint32(pid))
		}
	} else {
		logger.Debug("caps Requested", "error", err)
	}

	// Initialize capture directory

	if err := os.MkdirAll(t.config.Capture.OutputPath, 0755); err != nil {
		t.Close()
		return fmt.Errorf("error creating output path: %w", err)
	}

	t.outDir, err = utils.OpenExistingDir(t.config.Capture.OutputPath)
	if err != nil {
		t.Close()
		return fmt.Errorf("error opening out directory: %w", err)
	}

	// Initialize network capture (all needed pcap files)

	t.netCapturePcap, err = pcaps.New(t.config.Capture.Net, t.outDir)
	if err != nil {
		t.Close()
		return fmt.Errorf("error initializing network capture: %w", err)
	}

	// Get reference to stack trace addresses map

	stackAddressesMap, err := t.bpfModule.GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return fmt.Errorf("error getting access to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = stackAddressesMap

	// Get reference to fd arg path map

	fdArgPathMap, err := t.bpfModule.GetMap("fd_arg_path_map")
	if err != nil {
		t.Close()
		return fmt.Errorf("error getting access to 'fd_arg_path_map' eBPF Map %v", err)
	}
	t.FDArgPathMap = fdArgPathMap

	// Initialize events sorting (pipeline step)

	if t.config.Output.EventsSorting {
		t.eventsSorter, err = sorting.InitEventSorter()
		if err != nil {
			return err
		}
	}

	// Tracee bpf code uses monotonic clock as event timestamp. Get current
	// monotonic clock so tracee can calculate event timestamps relative to it.

	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	startTime := ts.Nano()

	// Calculate the boot time using the monotonic time (since this is the clock
	// we're using as a timestamp) Note: this is NOT the real boot time, as the
	// monotonic clock doesn't take into account system sleeps.

	bootTime := time.Now().UnixNano() - startTime

	// Initialize times

	t.startTime = uint64(startTime)
	t.bootTime = uint64(bootTime)

	return nil
}

func (t *Tracee) generateInitValues() (InitValues, error) {
	initVals := InitValues{}
	for evt := range t.events {
		def, exists := events.Definitions.GetSafe(evt)
		if !exists {
			return initVals, fmt.Errorf("event with id %d doesn't exist", evt)
		}
		if def.Dependencies.KSymbols != nil {
			initVals.kallsyms = true
		}
	}

	return initVals, nil
}

// Initialize tail calls program array
func (t *Tracee) initTailCall(mapName string, mapIndexes []uint32, progName string) error {
	bpfMap, err := t.bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}
	bpfProg, err := t.bpfModule.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("could not get BPF program %s: %v", progName, err)
	}
	fd := bpfProg.FileDescriptor()
	if fd < 0 {
		return fmt.Errorf("could not get BPF program FD for %s: %v", progName, err)
	}

	for _, index := range mapIndexes {
		def := events.Definitions.Get(events.ID(index))
		// attach internal syscall probes if needed from tailcalls
		if def.Syscall {
			err := t.probes.Attach(probes.SyscallEnter__Internal)
			if err != nil {
				return err
			}
			err = t.probes.Attach(probes.SyscallExit__Internal)
			if err != nil {
				return err
			}
		}
		err := bpfMap.Update(unsafe.Pointer(&index), unsafe.Pointer(&fd))
		if err != nil {
			return err
		}
	}
	return nil
}

// initDerivationTable initializes tracee's events.DerivationTable.
// we declare for each Event (represented through it's ID) to which other
// events it can be derived and the corresponding function to derive into that Event.
func (t *Tracee) initDerivationTable() error {
	// sanity check for containers dependency
	if t.containers == nil {
		return fmt.Errorf("nil tracee containers")
	}

	pathResolver := containers.InitPathResolver(&t.pidsInMntns)
	soLoader := sharedobjs.InitContainersSymbolsLoader(&pathResolver, 1024)

	symbolsLoadedFilters := map[string]filters.Filter{}
	for filterScope := range t.config.FilterScopes.Map() {
		maps.Copy(symbolsLoadedFilters, filterScope.ArgFilter.GetEventFilters(events.SymbolsLoaded))
	}
	watchedSymbols := []string{}
	whitelistedLibs := []string{}

	if len(symbolsLoadedFilters) > 0 {
		watchedSymbolsFilter, ok := symbolsLoadedFilters["symbols"].(*filters.StringFilter)
		if watchedSymbolsFilter != nil && ok {
			watchedSymbols = watchedSymbolsFilter.Equal()
		}
		whitelistedLibsFilter, ok := symbolsLoadedFilters["library_path"].(*filters.StringFilter)
		if whitelistedLibsFilter != nil && ok {
			whitelistedLibs = whitelistedLibsFilter.NotEqual()
		}
	}

	t.eventDerivations = derive.Table{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:        func() bool { return t.events[events.ContainerCreate].submit > 0 },
				DeriveFunction: derive.ContainerCreate(t.containers),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:        func() bool { return t.events[events.ContainerRemove].submit > 0 },
				DeriveFunction: derive.ContainerRemove(t.containers),
			},
		},
		events.PrintSyscallTable: {
			events.HookedSyscalls: {
				Enabled:        func() bool { return t.events[events.PrintSyscallTable].submit > 0 },
				DeriveFunction: derive.DetectHookedSyscall(t.kernelSymbols),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:        func() bool { return t.events[events.HookedSeqOps].submit > 0 },
				DeriveFunction: derive.HookedSeqOps(t.kernelSymbols),
			},
		},
		events.SharedObjectLoaded: {
			events.SymbolsLoaded: {
				Enabled: func() bool { return t.events[events.SymbolsLoaded].submit > 0 },
				DeriveFunction: derive.SymbolsLoaded(
					soLoader,
					watchedSymbols,
					whitelistedLibs,
				),
			},
		},
		//
		// Network Derivations
		//
		events.NetPacketIPBase: {
			events.NetPacketIPv4: {
				Enabled:        func() bool { return t.events[events.NetPacketIPv4].submit > 0 },
				DeriveFunction: derive.NetPacketIPv4(),
			},
			events.NetPacketIPv6: {
				Enabled:        func() bool { return t.events[events.NetPacketIPv6].submit > 0 },
				DeriveFunction: derive.NetPacketIPv6(),
			},
		},
		events.NetPacketTCPBase: {
			events.NetPacketTCP: {
				Enabled:        func() bool { return t.events[events.NetPacketTCP].submit > 0 },
				DeriveFunction: derive.NetPacketTCP(),
			},
		},
		events.NetPacketUDPBase: {
			events.NetPacketUDP: {
				Enabled:        func() bool { return t.events[events.NetPacketUDP].submit > 0 },
				DeriveFunction: derive.NetPacketUDP(),
			},
		},
		events.NetPacketICMPBase: {
			events.NetPacketICMP: {
				Enabled:        func() bool { return t.events[events.NetPacketICMP].submit > 0 },
				DeriveFunction: derive.NetPacketICMP(),
			},
		},
		events.NetPacketICMPv6Base: {
			events.NetPacketICMPv6: {
				Enabled:        func() bool { return t.events[events.NetPacketICMPv6].submit > 0 },
				DeriveFunction: derive.NetPacketICMPv6(),
			},
		},
		events.NetPacketDNSBase: {
			events.NetPacketDNS: {
				Enabled:        func() bool { return t.events[events.NetPacketDNS].submit > 0 },
				DeriveFunction: derive.NetPacketDNS(),
			},
			events.NetPacketDNSRequest: {
				Enabled:        func() bool { return t.events[events.NetPacketDNSRequest].submit > 0 },
				DeriveFunction: derive.NetPacketDNSRequest(),
			},
			events.NetPacketDNSResponse: {
				Enabled:        func() bool { return t.events[events.NetPacketDNSResponse].submit > 0 },
				DeriveFunction: derive.NetPacketDNSResponse(),
			},
		},
		events.NetPacketHTTPBase: {
			events.NetPacketHTTP: {
				Enabled:        func() bool { return t.events[events.NetPacketHTTP].submit > 0 },
				DeriveFunction: derive.NetPacketHTTP(),
			},
			events.NetPacketHTTPRequest: {
				Enabled:        func() bool { return t.events[events.NetPacketHTTPRequest].submit > 0 },
				DeriveFunction: derive.NetPacketHTTPRequest(),
			},
			events.NetPacketHTTPResponse: {
				Enabled:        func() bool { return t.events[events.NetPacketHTTPResponse].submit > 0 },
				DeriveFunction: derive.NetPacketHTTPResponse(),
			},
		},
	}

	return nil
}

// RegisterEventDerivation registers an event derivation handler for tracee to use in the event pipeline
func (t *Tracee) RegisterEventDerivation(deriveFrom events.ID, deriveTo events.ID, deriveCondition func() bool, deriveLogic derive.DeriveFunction) error {
	if t.eventDerivations == nil {
		return fmt.Errorf("tracee not initialized yet")
	}

	return t.eventDerivations.Register(deriveFrom, deriveTo, deriveCondition, deriveLogic)
}

// options config should match defined values in ebpf code
const (
	optExecEnv uint32 = 1 << iota
	optCaptureFiles
	optExtractDynCode
	optStackAddresses
	optCaptureModules
	optCgroupV1
	optProcessInfo
	optTranslateFDFilePath
)

func (t *Tracee) getOptionsConfig() uint32 {
	var cOptVal uint32

	if t.config.Output.ExecEnv {
		cOptVal = cOptVal | optExecEnv
	}
	if t.config.Output.StackAddresses {
		cOptVal = cOptVal | optStackAddresses
	}
	if t.config.Capture.FileWrite {
		cOptVal = cOptVal | optCaptureFiles
	}
	if t.config.Capture.Module {
		cOptVal = cOptVal | optCaptureModules
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

	return cOptVal
}

func (t *Tracee) computeConfigValues() []byte {
	// config_entry
	configVal := make([]byte, 256)

	// tracee_pid
	binary.LittleEndian.PutUint32(configVal[0:4], uint32(os.Getpid()))
	// options
	binary.LittleEndian.PutUint32(configVal[4:8], t.getOptionsConfig())
	// cgroup_v1_hid
	binary.LittleEndian.PutUint32(configVal[8:12], uint32(t.containers.GetDefaultCgroupHierarchyID()))
	// padding
	binary.LittleEndian.PutUint32(configVal[12:16], 0)

	for filterScope := range t.config.FilterScopes.Map() {
		byteIndex := filterScope.ID / 8
		bitOffset := filterScope.ID % 8

		// filter enabled scopes bitmask
		if filterScope.UIDFilter.Enabled() {
			// uid_filter_enabled_scopes
			configVal[16+byteIndex] |= 1 << bitOffset
		}
		if filterScope.PIDFilter.Enabled() {
			// pid_filter_enabled_scopes
			configVal[24+byteIndex] |= 1 << bitOffset
		}
		if filterScope.MntNSFilter.Enabled() {
			// mnt_ns_filter_enabled_scopes
			configVal[32+byteIndex] |= 1 << bitOffset
		}
		if filterScope.PidNSFilter.Enabled() {
			// pid_ns_filter_enabled_scopes
			configVal[40+byteIndex] |= 1 << bitOffset
		}
		if filterScope.UTSFilter.Enabled() {
			// uts_ns_filter_enabled_scopes
			configVal[48+byteIndex] |= 1 << bitOffset
		}
		if filterScope.CommFilter.Enabled() {
			// comm_filter_enabled_scopes
			configVal[56+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ContIDFilter.Enabled() {
			// cgroup_id_filter_enabled_scopes
			configVal[64+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ContFilter.Enabled() {
			// cont_filter_enabled_scopes
			configVal[72+byteIndex] |= 1 << bitOffset
		}
		if filterScope.NewContFilter.Enabled() {
			// new_cont_filter_enabled_scopes
			configVal[80+byteIndex] |= 1 << bitOffset
		}
		if filterScope.NewPidFilter.Enabled() {
			// new_pid_filter_enabled_scopes
			configVal[88+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ProcessTreeFilter.Enabled() {
			// proc_tree_filter_enabled_scopes
			configVal[96+byteIndex] |= 1 << bitOffset
		}
		if filterScope.BinaryFilter.Enabled() {
			// bin_path_filter_enabled_scopes
			configVal[104+byteIndex] |= 1 << bitOffset
		}
		if filterScope.Follow {
			// follow_filter_enabled_scopes
			configVal[112+byteIndex] |= 1 << bitOffset
		}

		// filter out scopes bitmask
		if filterScope.UIDFilter.FilterOut() {
			// uid_filter_out_scopes
			configVal[120+byteIndex] |= 1 << bitOffset
		}
		if filterScope.PIDFilter.FilterOut() {
			// pid_filter_out_scopes
			configVal[128+byteIndex] |= 1 << bitOffset
		}
		if filterScope.MntNSFilter.FilterOut() {
			// mnt_ns_filter_out_scopes
			configVal[136+byteIndex] |= 1 << bitOffset
		}
		if filterScope.PidNSFilter.FilterOut() {
			// pid_ns_filter_out_scopes
			configVal[144+byteIndex] |= 1 << bitOffset
		}
		if filterScope.UTSFilter.FilterOut() {
			// uts_ns_filter_out_scopes
			configVal[152+byteIndex] |= 1 << bitOffset
		}
		if filterScope.CommFilter.FilterOut() {
			// comm_filter_out_scopes
			configVal[160+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ContIDFilter.FilterOut() {
			// cgroup_id_filter_out_scopes
			configVal[168+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ContFilter.FilterOut() {
			// cont_filter_out_scopes
			configVal[176+byteIndex] |= 1 << bitOffset
		}
		if filterScope.NewContFilter.FilterOut() {
			// new_cont_filter_out_scopes
			configVal[184+byteIndex] |= 1 << bitOffset
		}
		if filterScope.NewPidFilter.FilterOut() {
			// new_pid_filter_out_scopes
			configVal[192+byteIndex] |= 1 << bitOffset
		}
		if filterScope.ProcessTreeFilter.FilterOut() {
			// proc_tree_filter_out_scopes
			configVal[200+byteIndex] |= 1 << bitOffset
		}
		if filterScope.BinaryFilter.FilterOut() {
			// bin_path_filter_out_scopes
			configVal[208+byteIndex] |= 1 << bitOffset
		}

		// enabled_scopes
		configVal[216+byteIndex] |= 1 << bitOffset
	}

	// compute all filter scopes internals
	t.config.FilterScopes.compute()

	// uid_max
	binary.LittleEndian.PutUint64(configVal[224:232], t.config.FilterScopes.UIDFilterMax())
	// uid_min
	binary.LittleEndian.PutUint64(configVal[232:240], t.config.FilterScopes.UIDFilterMin())
	// pid_max
	binary.LittleEndian.PutUint64(configVal[240:248], t.config.FilterScopes.PIDFilterMax())
	// pid_min
	binary.LittleEndian.PutUint64(configVal[248:256], t.config.FilterScopes.PIDFilterMin())

	return configVal
}

// validateKallsymsDependencies load all symbols required by events' dependencies from the kallsyms file to check for missing symbols.
// If some symbols are missing, it will cancel their event with informative error message.
func (t *Tracee) validateKallsymsDependencies() {
	var reqKsyms []string
	symsToDependentEvents := make(map[string][]events.ID)
	for id := range t.events {
		event := events.Definitions.Get(id)
		if event.Dependencies.KSymbols != nil {
			for _, symDep := range *event.Dependencies.KSymbols {
				reqKsyms = append(reqKsyms, symDep.Symbol)
				if symDep.Required {
					symEvents, ok := symsToDependentEvents[symDep.Symbol]
					if ok {
						symEvents = append(symEvents, id)
					} else {
						symEvents = []events.ID{id}
					}
					symsToDependentEvents[symDep.Symbol] = symEvents
				}
			}
		}
	}

	kallsymsValues := LoadKallsymsValues(t.kernelSymbols, reqKsyms)

	// Figuring out for each event if it has missing required symbols and which
	missingSymsPerEvent := make(map[events.ID][]string)
	for sym, depEventsIDs := range symsToDependentEvents {
		_, ok := kallsymsValues[sym]
		if ok {
			continue
		}
		for _, depEventID := range depEventsIDs {
			eventMissingSyms, ok := missingSymsPerEvent[depEventID]
			if ok {
				eventMissingSyms = append(eventMissingSyms, sym)
			} else {
				eventMissingSyms = []string{sym}
			}
			missingSymsPerEvent[depEventID] = eventMissingSyms
		}
	}

	// Cancel events with missing symbols dependencies
	for eventToCancel, missingDepSyms := range missingSymsPerEvent {
		logger.Error("event canceled because of missing kernel symbol dependency", "missing symbols", missingDepSyms, "event", events.Definitions.Get(eventToCancel).Name)
		delete(t.events, eventToCancel)
	}
}

func (t *Tracee) populateBPFMaps() error {
	// Prepare events map
	eventsMap, err := t.bpfModule.GetMap("events_map")
	if err != nil {
		return err
	}
	for id, ecfg := range t.events {
		submit := ecfg.submit
		err := eventsMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&submit))
		if err != nil {
			return err
		}
	}

	// Prepare 32bit to 64bit syscall number mapping
	sys32to64BPFMap, err := t.bpfModule.GetMap("sys_32_to_64_map") // u32, u32
	if err != nil {
		return err
	}
	for id, event := range events.Definitions.Events() {
		ID32BitU32 := uint32(event.ID32Bit) // ID32Bit is int32
		IDU32 := uint32(id)                 // ID is int32
		if err := sys32to64BPFMap.Update(unsafe.Pointer(&ID32BitU32), unsafe.Pointer(&IDU32)); err != nil {
			return err
		}
	}

	if t.kernelSymbols != nil {
		err = t.UpdateBPFKsymbolsMap()
		if err != nil {
			return err
		}
	}

	// Initialize kconfig variables (map used instead of relying in libbpf's .kconfig automated maps)
	// Note: this allows libbpf not to rely on the system kconfig file, tracee does the kconfig var identification job

	bpfKConfigMap, err := t.bpfModule.GetMap("kconfig_map") // u32, u32
	if err != nil {
		return err
	}

	kconfigValues, err := initialization.LoadKconfigValues(t.config.KernelConfig)
	if err != nil {
		return err
	}

	for key, value := range kconfigValues {
		keyU32 := uint32(key)
		valueU32 := uint32(value)
		err = bpfKConfigMap.Update(unsafe.Pointer(&keyU32), unsafe.Pointer(&valueU32))
		if err != nil {
			return err
		}
	}

	cZero := uint32(0)

	// net_packet configuration map
	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		bpfNetConfigMap, err := t.bpfModule.GetMap("netconfig_map")
		if err != nil {
			return err
		}

		netConfigVal := make([]byte, 8) // u32 capture_options, u32 capture_length

		options := pcaps.GetPcapOptions(t.config.Capture.Net)

		binary.LittleEndian.PutUint32(netConfigVal[0:4], uint32(options))
		binary.LittleEndian.PutUint32(netConfigVal[4:8], t.config.Capture.Net.CaptureLength)

		if err = bpfNetConfigMap.Update(
			unsafe.Pointer(&cZero),
			unsafe.Pointer(&netConfigVal[0]),
		); err != nil {
			return fmt.Errorf("error updating net config eBPF map: %v", err)
		}
	}

	// Initialize config map
	bpfConfigMap, err := t.bpfModule.GetMap("config_map")
	if err != nil {
		return err
	}

	configVal := t.computeConfigValues()
	if err = bpfConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(&configVal[0])); err != nil {
		return err
	}

	for filterScope := range t.config.FilterScopes.Map() {
		scopeID := uint(filterScope.ID)
		errMap := make(map[string]error, 0)

		errMap[UIDFilterMap] = filterScope.UIDFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[PIDFilterMap] = filterScope.PIDFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[MntNSFilterMap] = filterScope.MntNSFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[PidNSFilterMap] = filterScope.PidNSFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[UTSFilterMap] = filterScope.UTSFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[CommFilterMap] = filterScope.CommFilter.UpdateBPF(t.bpfModule, scopeID)
		errMap[ContIdFilter] = filterScope.ContIDFilter.UpdateBPF(t.bpfModule, t.containers, scopeID)
		errMap[BinaryFilterMap] = filterScope.BinaryFilter.UpdateBPF(t.bpfModule, scopeID)

		for k, v := range errMap {
			if v != nil {
				return fmt.Errorf("error setting %v filter: %v", k, v)
			}
		}
	}

	// Populate containers map with existing containers
	err = t.containers.PopulateBpfMap(t.bpfModule)
	if err != nil {
		return err
	}

	// Set filters given by the user to filter file write events
	fileFilterMap, err := t.bpfModule.GetMap("file_filter") // u32, u32
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(t.config.Capture.FilterFileWrite)); i++ {
		FilterFileWriteBytes := []byte(t.config.Capture.FilterFileWrite[i])
		if err = fileFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&FilterFileWriteBytes[0])); err != nil {
			return err
		}
	}

	// Initialize param types map
	eventsParams := make(map[events.ID][]bufferdecoder.ArgType)
	for id, eventDefinition := range events.Definitions.Events() {
		params := eventDefinition.Params
		for _, param := range params {
			eventsParams[id] = append(eventsParams[id], bufferdecoder.GetParamType(param.Type))
		}
	}
	paramsTypesBPFMap, err := t.bpfModule.GetMap("params_types_map") // u32, u64
	if err != nil {
		return err
	}
	for e := range t.events {
		eU32 := uint32(e) // e is int32
		params := eventsParams[e]
		var paramsTypes uint64
		for n, paramType := range params {
			paramsTypes = paramsTypes | (uint64(paramType) << (8 * n))
		}
		if err := paramsTypesBPFMap.Update(unsafe.Pointer(&eU32), unsafe.Pointer(&paramsTypes)); err != nil {
			return err
		}
	}

	_, ok := t.events[events.HookedSyscalls]
	if ok {
		syscallsToCheckMap, err := t.bpfModule.GetMap("syscalls_to_check_map")
		if err != nil {
			return err
		}
		/* the syscallsToCheckMap store the syscall numbers that we are fetching from the syscall table, like that:
		 * [syscall num #1][syscall num #2][syscall num #3]...
		 * with that, we can fetch the syscall address by accessing the syscall table in the syscall number index
		 */

		for idx, val := range events.SyscallsToCheck() {
			err = syscallsToCheckMap.Update(unsafe.Pointer(&(idx)), unsafe.Pointer(&val))
			if err != nil {
				return err
			}
		}
	}

	// Initialize tail call dependencies
	tailCalls, err := t.GetTailCalls()
	if err != nil {
		return err
	}
	for _, tailCall := range tailCalls {
		err := t.initTailCall(tailCall.MapName, tailCall.MapIndexes, tailCall.ProgName)
		if err != nil {
			return fmt.Errorf("failed to initialize tail call: %w", err)
		}
	}

	return nil
}

// getTailCalls collects all tailcall dependencies from required events, and generates additional tailcall per syscall traced.
// for syscall tracing, there are 4 different relevant tail calls:
// 1. sys_enter_init - syscall data saving is done here
// 2. sys_enter_submit - some syscall submits are done here
// 3. sys_exit_init - syscall validation on exit is done here
// 4. sys_exit_submit - most syscalls are submitted at this point
// this division is done because some events only require the syscall saving logic and not event submitting.
// as such in order to actually track syscalls we need to initialize these 4 tail calls per syscall event requested for submission.
// in pkg/events/events.go one can see that some events will require the sys_enter_init tail call, this is because they require syscall data saving
// in their probe (for example security_file_open needs open, openat and openat2).
func getTailCalls(eventConfigs map[events.ID]eventConfig) ([]events.TailCall, error) {
	enterInitTailCall := events.TailCall{MapName: "sys_enter_init_tail", MapIndexes: []uint32{}, ProgName: "sys_enter_init"}
	enterSubmitTailCall := events.TailCall{MapName: "sys_enter_submit_tail", MapIndexes: []uint32{}, ProgName: "sys_enter_submit"}
	exitInitTailCall := events.TailCall{MapName: "sys_exit_init_tail", MapIndexes: []uint32{}, ProgName: "sys_exit_init"}
	exitSubmitTailCall := events.TailCall{MapName: "sys_exit_submit_tail", MapIndexes: []uint32{}, ProgName: "sys_exit_submit"}
	// for tracking only unique tail call, we use it's string form as the key in a "set" map (map[string]bool)
	// we use a string and not the struct itself because it includes an array.
	// in golang, map keys must be a comparable type, which are numerics and strings. structs can also be used as
	// keys, but only if they are composed solely from comparable types.
	// arrays/slices are not comparable, so we need to use the string form of the struct as a key instead.
	// we then only append the actual tail call struct to a list if it's string form is not found in the map.
	tailCallProgs := map[string]bool{}
	tailCalls := []events.TailCall{}
	for e, cfg := range eventConfigs {
		def := events.Definitions.Get(e)
		for _, tailCall := range def.Dependencies.TailCalls {
			if len(tailCall.MapIndexes) == 0 {
				// if tailcall has no indexes defined we can skip it
				continue
			}
			for _, index := range tailCall.MapIndexes {
				if index >= uint32(events.MaxCommonID) { // remove undefined syscalls (check arm64.go) and events
					logger.Debug("removing index from tail call (over max event id)", "tail_call_map", tailCall.MapName, "index", index,
						"max_event_id", events.MaxCommonID, "pkgName", pkgName)
					tailCall.RemoveIndex(index)
				}
			}
			tailCallStr := fmt.Sprint(tailCall)
			if !tailCallProgs[tailCallStr] {
				tailCalls = append(tailCalls, tailCall)
			}
			tailCallProgs[tailCallStr] = true
		}
		// validate the event and add to the syscall tail calls
		if def.Syscall && cfg.submit > 0 && e < events.MaxSyscallID {
			enterInitTailCall.AddIndex(uint32(e))
			enterSubmitTailCall.AddIndex(uint32(e))
			exitInitTailCall.AddIndex(uint32(e))
			exitSubmitTailCall.AddIndex(uint32(e))
		}
	}
	tailCalls = append(tailCalls, enterInitTailCall, enterSubmitTailCall, exitInitTailCall, exitSubmitTailCall)
	return tailCalls, nil
}

func (t *Tracee) GetTailCalls() ([]events.TailCall, error) {
	return getTailCalls(t.events)
}

// attachProbes attaches selected events probes to their respective eBPF progs
func (t *Tracee) attachProbes() error {
	var err error

	// attach selected tracing events probes

	for tr := range t.events {
		event, ok := events.Definitions.GetSafe(tr)
		if !ok {
			continue
		}

		// attach internal syscall probes for selected syscall events, if any
		if event.Syscall {
			err := t.probes.Attach(probes.SyscallEnter__Internal)
			if err != nil {
				return err
			}
			err = t.probes.Attach(probes.SyscallExit__Internal)
			if err != nil {
				return err
			}
		}

		// attach probes for selected events
		for _, dep := range event.Probes {
			err = t.probes.Attach(dep.Handle, t.cgroups)
			if err != nil && dep.Required {
				return fmt.Errorf("failed to attach required probe: %v", err)
			}
		}
	}

	return nil
}

func (t *Tracee) initBPF() error {
	var err error

	// Execute code with higher privileges: ring1 (required)

	err = capabilities.GetInstance().Required(func() error {

		newModuleArgs := bpf.NewModuleArgs{
			KConfigFilePath: t.config.KernelConfig.GetKernelConfigFilePath(),
			BTFObjPath:      t.config.BTFObjPath,
			BPFObjBuff:      t.config.BPFObjBytes,
			BPFObjName:      t.config.BPFObjPath,
		}

		// Open the eBPF object file (create a new module)

		t.bpfModule, err = bpf.NewModuleFromBufferArgs(newModuleArgs)
		if err != nil {
			return err
		}

		// Initialize probes

		t.probes, err = probes.Init(t.bpfModule, t.netEnabled())
		if err != nil {
			return err
		}

		// Load the eBPF object into kernel

		err = t.bpfModule.BPFLoadObject()
		if err != nil {
			return err
		}

		// Populate eBPF maps with initial data

		err = t.populateBPFMaps()
		if err != nil {
			return err
		}

		// Attach eBPF programs to selected event's probes

		err = t.attachProbes()
		if err != nil {
			return err
		}

		// Update all ProcessTreeFilters after probes are attached: reduce the
		// possible race window between the bpf programs updating the maps and
		// userland reading procfs and also dealing with same maps.
		for filterScope := range t.config.FilterScopes.Map() {
			err = filterScope.ProcessTreeFilter.UpdateBPF(t.bpfModule, uint(filterScope.ID))
			if err != nil {
				return fmt.Errorf("error building process tree: %v", err)
			}
		}

		// Initialize perf buffers

		t.eventsChannel = make(chan []byte, 1000)
		t.lostEvChannel = make(chan uint64)
		if t.config.PerfBufferSize < 1 {
			return fmt.Errorf("invalid perf buffer size: %d", t.config.PerfBufferSize)
		}
		t.eventsPerfMap, err = t.bpfModule.InitPerfBuf(
			"events",
			t.eventsChannel,
			t.lostEvChannel,
			t.config.PerfBufferSize,
		)
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}

		if t.config.BlobPerfBufferSize > 0 {
			t.fileWrChannel = make(chan []byte, 1000)
			t.lostWrChannel = make(chan uint64)
			t.fileWrPerfMap, err = t.bpfModule.InitPerfBuf(
				"file_writes",
				t.fileWrChannel,
				t.lostWrChannel,
				t.config.BlobPerfBufferSize,
			)
			if err != nil {
				return fmt.Errorf("error initializing file_writes perf map: %v", err)
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
				return fmt.Errorf("error initializing net capture perf map: %v", err)
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
			return fmt.Errorf("error initializing logs perf map: %v", err)
		}

		return nil
	})

	return err
}

// Run starts the trace. it will run until ctx is cancelled
func (t *Tracee) Run(ctx gocontext.Context) error {
	t.invokeInitEvents()
	t.triggerSyscallsIntegrityCheck(trace.Event{})
	t.triggerSeqOpsIntegrityCheck(trace.Event{})
	err := t.triggerMemDump(trace.Event{})
	if err != nil {
		logger.Warn("memory dump", "error", err)
	}
	t.eventsPerfMap.Start()
	go t.processLostEvents()
	go t.handleEvents(ctx)
	if t.config.BlobPerfBufferSize > 0 {
		t.fileWrPerfMap.Start()
		go t.processFileWrites()
	}
	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		t.netCapPerfMap.Start()
		go t.processNetCaptureEvents(ctx)
	}
	t.bpfLogsPerfMap.Start()
	go t.processBPFLogs()
	t.running = true

	// write pid file
	err = t.writePid()
	if err != nil {
		// not able to write pid, abort
		return err
	}

	// block until ctx is cancelled elsewhere
	<-ctx.Done()

	t.eventsPerfMap.Stop()
	if t.config.BlobPerfBufferSize > 0 {
		t.fileWrPerfMap.Stop()
	}
	if pcaps.PcapsEnabled(t.config.Capture.Net) {
		t.netCapPerfMap.Stop()
	}
	t.bpfLogsPerfMap.Stop()

	// record index of written files
	if t.config.Capture.FileWrite {
		destinationFilePath := "written_files"
		f, err := utils.OpenAt(t.outDir, destinationFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error logging written files")
		}
		defer f.Close()
		for fileName, filePath := range t.writtenFiles {
			writeFiltered := false
			for _, filterPrefix := range t.config.Capture.FilterFileWrite {
				if !strings.HasPrefix(filePath, filterPrefix) {
					writeFiltered = true
					break
				}
			}
			if writeFiltered {
				// Don't write mapping of files that were not actually captured
				continue
			}
			if _, err := f.WriteString(fmt.Sprintf("%s %s\n", fileName, filePath)); err != nil {
				return fmt.Errorf("error logging written files")
			}
		}
	}

	t.Close()
	return nil
}

// Close cleans up created resources
func (t *Tracee) Close() {
	err := capabilities.GetInstance().Required(
		func() error {
			if t.probes != nil {
				err := t.probes.DetachAll()
				if err != nil {
					return fmt.Errorf("failed to detach probes when closing tracee: %s", err)
				}
			}
			if t.bpfModule != nil {
				t.bpfModule.Close()
			}
			if t.containers != nil {
				err := t.containers.Close()
				if err != nil {
					return fmt.Errorf("failed to clean containers module when closing tracee: %s", err)
				}
			}
			t.running = false
			return nil
		},
	)
	if err != nil {
		logger.Error("capabilities", "error", err)
	}

	err = t.cgroups.Destroy()
	if err != nil {
		logger.Error("cgroups destroy", "error", err)
	}
}

func (t *Tracee) Running() bool {
	return t.running
}

func (t *Tracee) computeOutFileHash(fileName string) (string, error) {
	f, err := utils.OpenAt(t.outDir, fileName, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return computeFileHash(f)
}

func computeFileHashAtPath(fileName string) (string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return computeFileHash(f)
}

func computeFileHash(file *os.File) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (t *Tracee) invokeInitEvents() {
	if t.events[events.InitNamespaces].emit > 0 {
		capabilities.GetInstance().Requested(func() error { // ring2
			systemInfoEvent := events.InitNamespacesEvent()
			t.config.ChanEvents <- systemInfoEvent
			return nil
		}, cap.SYS_PTRACE)
		t.stats.EventCount.Increment()
	}
	if t.events[events.ExistingContainer].emit > 0 {
		for _, e := range events.ExistingContainersEvents(t.containers, t.config.ContainersEnrich) {
			t.config.ChanEvents <- e
			t.stats.EventCount.Increment()
		}
	}
}

// netEnabled returns true if any base network event is to be traced
func (t *Tracee) netEnabled() bool {
	for k := range t.events {
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

const uProbeMagicNumber uint64 = 20220829

// triggerSyscallsIntegrityCheck is used by a Uprobe to trigger an eBPF program
// that prints the syscall table
func (t *Tracee) triggerSyscallsIntegrityCheck(event trace.Event) {
	_, ok := t.events[events.HookedSyscalls]
	if !ok {
		return
	}
	eventHandle := t.triggerContexts.Store(event)
	t.triggerSyscallsIntegrityCheckCall(
		uProbeMagicNumber,
		uint64(eventHandle),
	)
}

//go:noinline
func (t *Tracee) triggerSyscallsIntegrityCheckCall(
	magicNumber uint64, // 1st arg: allow handler to detect calling convention
	eventHandle uint64) {
}

// triggerSeqOpsIntegrityCheck is used by a Uprobe to trigger an eBPF program
// that prints the seq ops pointers
func (t *Tracee) triggerSeqOpsIntegrityCheck(event trace.Event) {
	_, ok := t.events[events.HookedSeqOps]
	if !ok {
		return
	}
	var seqOpsPointers [len(derive.NetSeqOps)]uint64
	for i, seqName := range derive.NetSeqOps {
		seqOpsStruct, err := t.kernelSymbols.GetSymbolByName("system", seqName)
		if err != nil {
			continue
		}
		seqOpsPointers[i] = seqOpsStruct.Address
	}
	eventHandle := t.triggerContexts.Store(event)
	t.triggerSeqOpsIntegrityCheckCall(
		uProbeMagicNumber,
		uint64(eventHandle),
		seqOpsPointers,
	)
}

//go:noinline
func (t *Tracee) triggerSeqOpsIntegrityCheckCall(
	magicNumber uint64, // 1st arg: allow handler to detect calling convention
	eventHandle uint64,
	seqOpsStruct [len(derive.NetSeqOps)]uint64) error {
	return nil
}

// triggerMemDump is used by a Uprobe to trigger an eBPF program
// that prints the first bytes of requested symbols or addresses
func (t *Tracee) triggerMemDump(event trace.Event) error {
	if _, ok := t.events[events.PrintMemDump]; !ok {
		return nil
	}

	errArgFilter := make(map[int]error, 0)

	for filterScope := range t.config.FilterScopes.Map() {
		printMemDumpFilters := filterScope.ArgFilter.GetEventFilters(events.PrintMemDump)
		if printMemDumpFilters == nil {
			errArgFilter[filterScope.ID] = fmt.Errorf("scope %d: no address or symbols were provided to print_mem_dump event. "+
				"please provide it via -t print_mem_dump.args.address=<hex address>"+
				", -t print_mem_dump.args.symbol_name=<owner>:<symbol> or "+
				"-t print_mem_dump.args.symbol_name=<symbol> if specifying a system owned symbol", filterScope.ID)

			continue
		}

		eventHandle := t.triggerContexts.Store(event)

		lengthFilter, ok := printMemDumpFilters["length"].(*filters.StringFilter)
		var length uint64
		var err error
		if lengthFilter == nil || !ok || len(lengthFilter.Equal()) == 0 {
			length = maxMemDumpLength // default mem dump length
		} else {
			for _, field := range lengthFilter.Equal() {
				length, err = strconv.ParseUint(field, 10, 64)
				if err != nil {
					return err
				}
				//lint:ignore SA4004 we only want the first argument
				break
			}
		}

		addressFilter, ok := printMemDumpFilters["address"].(*filters.StringFilter)
		if addressFilter != nil && ok {
			for _, field := range addressFilter.Equal() {
				address, err := strconv.ParseUint(field, 16, 64)
				if err != nil {
					return err
				}
				t.triggerMemDumpCall(address, length, uint64(eventHandle))
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
					return fmt.Errorf("invalid symbols provided %s - more than one ':' provided", field)
				}
				symbol, err := t.kernelSymbols.GetSymbolByName(owner, name)
				if err != nil {
					return err
				}
				t.triggerMemDumpCall(symbol.Address, length, uint64(eventHandle))
			}
		}
	}

	for k, v := range errArgFilter {
		if v != nil {
			return fmt.Errorf("error setting %v filter: %v", k, v)
		}
	}

	return nil
}

//go:noinline
func (t *Tracee) triggerMemDumpCall(address uint64, length uint64, eventHandle uint64) error {
	return nil
}

// Initialize PID file
func (t *Tracee) writePid() error {
	pidFile, err := utils.OpenAt(t.outDir, "tracee.pid", syscall.O_WRONLY|syscall.O_CREAT, 0640)
	if err != nil {
		return fmt.Errorf("error creating readiness file: %w", err)
	}

	_, err = pidFile.Write([]byte(strconv.Itoa(os.Getpid()) + "\n"))
	if err != nil {
		return fmt.Errorf("error writing to readiness file: %w", err)
	}

	return nil
}
