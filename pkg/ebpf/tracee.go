package ebpf

import (
	gocontext "context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/ebpf/initialization"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/events/queue"
	"github.com/aquasecurity/tracee/pkg/events/sorting"
	"github.com/aquasecurity/tracee/pkg/events/trigger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/procinfo"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/sys/unix"
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	Filter             *Filter
	Capture            *CaptureConfig
	Output             *OutputConfig
	Cache              queue.CacheConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	Debug              bool
	maxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath         string
	BPFObjPath         string
	BPFObjBytes        []byte
	KernelConfig       *helpers.KernelConfig
	ChanEvents         chan trace.Event
	ChanErrors         chan error
	ProcessInfo        bool
	OSInfo             *helpers.OSInfo
	Sockets            runtime.Sockets
	ContainersEnrich   bool
}

type CaptureConfig struct {
	OutputPath      string
	FileWrite       bool
	Module          bool
	FilterFileWrite []string
	Exec            bool
	Mem             bool
	Profile         bool
	NetIfaces       *NetIfaces
	NetPerContainer bool
	NetPerProcess   bool
}

type OutputConfig struct {
	StackAddresses    bool
	DetectSyscall     bool
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
	if tc.Filter == nil || tc.Filter.EventsToTrace == nil {
		return fmt.Errorf("Filter or EventsToTrace is nil")
	}

	for _, e := range tc.Filter.EventsToTrace {
		def, exists := events.Definitions.GetSafe(e)
		if !exists {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
		if isNetEvent(e) {
			if len(tc.Filter.NetFilter.Interfaces()) == 0 {
				return fmt.Errorf("missing interface for net event: %s, please add -t net=<iface>", def.Name)
			}
		}
	}
	for eventID, eventFilters := range tc.Filter.ArgFilter.Filters {
		for argName := range eventFilters {
			eventDefinition, ok := events.Definitions.GetSafe(eventID)
			if !ok {
				return fmt.Errorf("invalid argument filter event id: %d", eventID)
			}
			eventParams := eventDefinition.Params
			// check if argument name exists for this event
			argFound := false
			for i := range eventParams {
				if eventParams[i].Name == argName {
					argFound = true
					break
				}
			}
			if !argFound {
				return fmt.Errorf("invalid argument filter argument name: %s", argName)
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

	if tc.ChanErrors == nil {
		return errors.New("nil errors channel")
	}

	return nil
}

type profilerInfo struct {
	Times            int64  `json:"times,omitempty"`
	FileHash         string `json:"file_hash,omitempty"`
	FirstExecutionTs uint64 `json:"-"`
}

type fileExecInfo struct {
	LastCtime int64
	Hash      string
}

type eventConfig struct {
	submit bool // event should be submitted to userspace
	emit   bool // event should be emitted to the user
}

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config            Config
	probes            probes.Probes
	events            map[events.ID]eventConfig
	bpfModule         *bpf.Module
	eventsPerfMap     *bpf.PerfBuffer
	fileWrPerfMap     *bpf.PerfBuffer
	netPerfMap        *bpf.PerfBuffer
	eventsChannel     chan []byte
	fileWrChannel     chan []byte
	netChannel        chan []byte
	lostEvChannel     chan uint64
	lostWrChannel     chan uint64
	lostNetChannel    chan uint64
	bootTime          uint64
	startTime         uint64
	stats             metrics.Stats
	capturedFiles     map[string]int64
	fileHashes        *lru.Cache
	profiledFiles     map[string]profilerInfo
	writtenFiles      map[string]string
	pidsInMntns       bucketscache.BucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
	StackAddressesMap *bpf.BPFMap
	FDArgPathMap      *bpf.BPFMap
	netInfo           netInfo
	containers        *containers.Containers
	procInfo          *procinfo.ProcInfo
	eventsSorter      *sorting.EventsChronologicalSorter
	eventDerivations  derive.Table
	kernelSymbols     *helpers.KernelSymbolTable
	triggerContexts   trigger.Context
	running           bool
	outDir            *os.File // All file operations to output dir should be through the utils package file operations (like utils.OpenAt) using this directory file.
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
		events.CgroupMkdir:      {submit: true},
		events.CgroupRmdir:      {submit: true},
	}
}

// GetCaptureEventsList sets events used to capture data
func GetCaptureEventsList(cfg Config) map[events.ID]eventConfig {
	captureEvents := make(map[events.ID]eventConfig)

	if cfg.Capture.Exec {
		captureEvents[events.CaptureExec] = eventConfig{}
	}
	if cfg.Capture.FileWrite {
		captureEvents[events.CaptureFileWrite] = eventConfig{}
	}
	if cfg.Capture.Module {
		captureEvents[events.CaptureModule] = eventConfig{}
	}
	if cfg.Capture.Mem {
		captureEvents[events.CaptureMem] = eventConfig{}
	}
	if cfg.Capture.Profile {
		captureEvents[events.CaptureProfile] = eventConfig{}
	}
	if cfg.Capture.NetIfaces != nil {
		captureEvents[events.CapturePcap] = eventConfig{}
	}
	if len(cfg.Filter.NetFilter.Ifaces) > 0 || cfg.Debug {
		captureEvents[events.SecuritySocketBind] = eventConfig{}
	}

	return captureEvents
}

func (t *Tracee) handleEventsDependencies(eventId events.ID) {
	definition := events.Definitions.Get(eventId)
	eDependencies := definition.Dependencies
	for _, dependentEvent := range eDependencies.Events {
		ec, ok := t.events[dependentEvent.EventID]
		if !ok {
			ec = eventConfig{}
			t.handleEventsDependencies(dependentEvent.EventID)
		}
		ec.submit = true
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

	// create tracee
	t := &Tracee{
		config:        cfg,
		writtenFiles:  make(map[string]string),
		capturedFiles: make(map[string]int64),
		events:        GetEssentialEventsList(),
	}

	for eventID, eCfg := range GetCaptureEventsList(cfg) {
		t.events[eventID] = eCfg
	}

	// Events chosen by the user
	for _, e := range t.config.Filter.EventsToTrace {
		t.events[e] = eventConfig{submit: true, emit: true}
	}

	// Handles all essential events dependencies
	for id := range t.events {
		t.handleEventsDependencies(id)
	}

	t.netInfo.ifaces = make(map[int]*net.Interface)
	t.netInfo.ifacesConfig = make(map[string]int32)
	for _, iface := range t.config.Filter.NetFilter.Ifaces {
		netIface, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("invalid network interface: %s", iface)
		}
		// Map real network interface index to interface object
		t.netInfo.ifaces[netIface.Index] = netIface
		t.netInfo.ifacesConfig[netIface.Name] |= events.TraceIface
	}

	if t.config.Capture.NetIfaces != nil {
		for _, iface := range t.config.Capture.NetIfaces.Interfaces() {
			netIface, err := net.InterfaceByName(iface)
			if err != nil {
				return nil, fmt.Errorf("invalid network interface: %s", iface)
			}
			if !t.netInfo.hasIface(netIface.Name) {
				// Map real network interface index to interface object
				t.netInfo.ifaces[netIface.Index] = netIface
			}
			t.netInfo.ifacesConfig[netIface.Name] |= events.CaptureIface
		}
	}

	t.triggerContexts = trigger.NewContext()

	return t, nil
}

// Initialize tracee instance and it's various subsystems, potentially performing external system operations to initialize them
// NOTE: any initialization logic, especially one that causes side effects, should go here and not New().
func (t *Tracee) Init() error {
	initReq, err := t.generateInitValues()
	if err != nil {
		return fmt.Errorf("failed to generate required init values: %s", err)
	}

	if initReq.kallsyms {
		t.kernelSymbols, err = helpers.NewKernelSymbolsMap()
		if err != nil {
			t.Close()
			return fmt.Errorf("error creating symbols map: %v", err)
		}
		if !initialization.ValidateKsymbolsTable(t.kernelSymbols) {
			return fmt.Errorf("kernel symbols were not loaded currectly. Make sure tracee-ebpf has the CAP_SYSLOG capability")
		}
	}

	// the process-tree initialize must be before we start receiving events to ensure we already have the needed data for the events that use that tree
	t.procInfo, err = procinfo.NewProcessInfo()
	if err != nil {
		t.Close()
		return fmt.Errorf("error creating process tree: %v", err)
	}

	t.containers, err = containers.New(t.config.Sockets, "containers_map", t.config.Debug)
	if err != nil {
		return fmt.Errorf("error initializing containers: %w", err)
	}
	if err := t.containers.Populate(); err != nil {
		return fmt.Errorf("error initializing containers: %w", err)
	}

	// Initialize event derivation map
	err = t.initDerivationTable()
	if err != nil {
		return fmt.Errorf("error intitalizing event derivation map: %w", err)
	}

	err = t.initBPF()
	if err != nil {
		t.Close()
		return err
	}

	t.fileHashes, err = lru.New(1024)
	if err != nil {
		t.Close()
		return err
	}
	t.profiledFiles = make(map[string]profilerInfo)
	//set a default value for config.maxPidsCache
	if t.config.maxPidsCache == 0 {
		t.config.maxPidsCache = 5
	}
	t.pidsInMntns.Init(t.config.maxPidsCache)

	hostMntnsLink, err := os.Readlink("/proc/1/ns/mnt")
	if err == nil {
		hostMntnsString := strings.TrimSuffix(strings.TrimPrefix(hostMntnsLink, "mnt:["), "]")
		hostMntns, err := strconv.Atoi(hostMntnsString)
		if err == nil {
			t.pidsInMntns.AddBucketItem(uint32(hostMntns), 1)
		}
	}

	if err := os.MkdirAll(t.config.Capture.OutputPath, 0755); err != nil {
		t.Close()
		return fmt.Errorf("error creating output path: %w", err)
	}

	t.outDir, err = utils.OpenExistingDir(t.config.Capture.OutputPath)
	if err != nil {
		t.Close()
		return fmt.Errorf("error opening out directory: %w", err)
	}
	pidFile, err := utils.OpenAt(t.outDir, "tracee.pid", syscall.O_WRONLY|syscall.O_CREAT, 0640)
	if err != nil {
		t.Close()
		return fmt.Errorf("error creating readiness file: %w", err)
	}
	_, err = pidFile.Write([]byte(strconv.Itoa(os.Getpid()) + "\n"))
	if err != nil {
		t.Close()
		return fmt.Errorf("error writing to readiness file: %w", err)
	}

	t.netInfo.pcapWriters, err = lru.NewWithEvict(openPcapsLimit, t.netInfo.PcapWriterOnEvict)
	if err != nil {
		t.Close()
		return err
	}

	// Get reference to stack trace addresses map
	stackAddressesMap, err := t.bpfModule.GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return fmt.Errorf("error getting acces to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = stackAddressesMap

	// Get reference to fd arg path map
	fdArgPathMap, err := t.bpfModule.GetMap("fd_arg_path_map")
	if err != nil {
		t.Close()
		return fmt.Errorf("error getting access to 'fd_arg_path_map' eBPF Map %v", err)
	}
	t.FDArgPathMap = fdArgPathMap

	if t.config.Output.EventsSorting {
		t.eventsSorter, err = sorting.InitEventSorter()
		if err != nil {
			return err
		}
	}

	// Tracee bpf code uses monotonic clock as event timestamp.
	// Get current monotonic clock so we can calculate event timestamps relative to it.
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	startTime := ts.Nano()
	// Calculate the boot time using the monotonic time (since this is the clock we're using as a timestamp)
	// Note: this is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

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
		if len(def.Dependencies.KSymbols) > 0 {
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

	t.eventDerivations = derive.Table{
		events.CgroupMkdir: {
			events.ContainerCreate: {
				Enabled:        t.events[events.ContainerCreate].submit,
				DeriveFunction: derive.ContainerCreate(t.containers),
			},
		},
		events.CgroupRmdir: {
			events.ContainerRemove: {
				Enabled:        t.events[events.ContainerRemove].submit,
				DeriveFunction: derive.ContainerRemove(t.containers),
			},
		},
		events.PrintSyscallTable: {
			events.HookedSyscalls: {
				Enabled:        t.events[events.PrintSyscallTable].submit,
				DeriveFunction: derive.DetectHookedSyscall(t.kernelSymbols),
			},
		},
		events.DnsRequest: {
			events.NetPacket: {
				Enabled:        t.events[events.NetPacket].submit,
				DeriveFunction: derive.NetPacket(),
			},
		},
		events.DnsResponse: {
			events.NetPacket: {
				Enabled:        t.events[events.NetPacket].submit,
				DeriveFunction: derive.NetPacket(),
			},
		},
		events.PrintNetSeqOps: {
			events.HookedSeqOps: {
				Enabled:        t.events[events.HookedSeqOps].submit,
				DeriveFunction: derive.HookedSeqOps(t.kernelSymbols),
			},
		},
		events.SharedObjectLoaded: {
			events.SymbolsLoaded: {
				Enabled: t.events[events.SymbolsLoaded].submit,
				DeriveFunction: derive.SymbolsLoaded(
					soLoader,
					t.config.Filter.ArgFilter.Filters[events.SymbolsLoaded]["symbols"].Equal,
					t.config.Filter.ArgFilter.Filters[events.SymbolsLoaded]["library_path"].NotEqual,
					t.config.Debug,
				),
			},
		},
	}

	return nil
}

// options config should match defined values in ebpf code
const (
	optDetectOrigSyscall uint32 = 1 << iota
	optExecEnv
	optCaptureFiles
	optExtractDynCode
	optStackAddresses
	optCaptureModules
	optCgroupV1
	optProcessInfo
	optTranslateFDFilePath
)

// filters config should match defined values in ebpf code
const (
	filterUIDEnabled uint32 = 1 << iota
	filterUIDOut
	filterMntNsEnabled
	filterMntNsOut
	filterPidNsEnabled
	filterPidNsOut
	filterUTSNsEnabled
	filterUTSNsOut
	filterCommEnabled
	filterCommOut
	filterPidEnabled
	filterPidOut
	filterContEnabled
	filterContOut
	filterFollowEnabled
	filterNewPidEnabled
	filterNewPidOut
	filterNewContEnabled
	filterNewContOut
	filterProcTreeEnabled
	filterProcTreeOut
	filterCgroupIdEnabled
	filterCgroupIdOut
)

func (t *Tracee) getOptionsConfig() uint32 {
	var cOptVal uint32

	if t.config.Output.DetectSyscall {
		cOptVal = cOptVal | optDetectOrigSyscall
	}
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
	if t.containers.IsCgroupV1() {
		cOptVal = cOptVal | optCgroupV1
	}
	if t.config.Capture.NetIfaces != nil || len(t.config.Filter.NetFilter.Interfaces()) > 0 || t.config.Debug {
		cOptVal = cOptVal | optProcessInfo
		t.config.ProcessInfo = true
	}
	if t.config.Output.ParseArgumentsFDs {
		cOptVal = cOptVal | optTranslateFDFilePath
	}

	return cOptVal
}

func (t *Tracee) getFiltersConfig() uint32 {
	var cFilterVal uint32
	if t.config.Filter.UIDFilter.Enabled {
		cFilterVal = cFilterVal | filterUIDEnabled
		if t.config.Filter.UIDFilter.FilterOut() {
			cFilterVal = cFilterVal | filterUIDOut
		}
	}
	if t.config.Filter.PIDFilter.Enabled {
		cFilterVal = cFilterVal | filterPidEnabled
		if t.config.Filter.PIDFilter.FilterOut() {
			cFilterVal = cFilterVal | filterPidOut
		}
	}
	if t.config.Filter.NewPidFilter.Enabled {
		cFilterVal = cFilterVal | filterNewPidEnabled
		if t.config.Filter.NewPidFilter.FilterOut() {
			cFilterVal = cFilterVal | filterNewPidOut
		}
	}
	if t.config.Filter.MntNSFilter.Enabled {
		cFilterVal = cFilterVal | filterMntNsEnabled
		if t.config.Filter.MntNSFilter.FilterOut() {
			cFilterVal = cFilterVal | filterMntNsOut
		}
	}
	if t.config.Filter.PidNSFilter.Enabled {
		cFilterVal = cFilterVal | filterPidNsEnabled
		if t.config.Filter.PidNSFilter.FilterOut() {
			cFilterVal = cFilterVal | filterPidNsOut
		}
	}
	if t.config.Filter.UTSFilter.Enabled {
		cFilterVal = cFilterVal | filterUTSNsEnabled
		if t.config.Filter.UTSFilter.FilterOut() {
			cFilterVal = cFilterVal | filterUTSNsOut
		}
	}
	if t.config.Filter.CommFilter.Enabled {
		cFilterVal = cFilterVal | filterCommEnabled
		if t.config.Filter.CommFilter.FilterOut() {
			cFilterVal = cFilterVal | filterCommOut
		}
	}
	if t.config.Filter.ContFilter.Enabled {
		cFilterVal = cFilterVal | filterContEnabled
		if t.config.Filter.ContFilter.FilterOut() {
			cFilterVal = cFilterVal | filterContOut
		}
	}
	if t.config.Filter.NewContFilter.Enabled {
		cFilterVal = cFilterVal | filterNewContEnabled
		if t.config.Filter.NewContFilter.FilterOut() {
			cFilterVal = cFilterVal | filterNewContOut
		}
	}
	if t.config.Filter.ContIDFilter.Enabled {
		cFilterVal = cFilterVal | filterCgroupIdEnabled
		if t.config.Filter.ContIDFilter.FilterOut() {
			cFilterVal = cFilterVal | filterCgroupIdOut
		}
	}
	if t.config.Filter.ProcessTreeFilter.Enabled {
		cFilterVal = cFilterVal | filterProcTreeEnabled
		if t.config.Filter.ProcessTreeFilter.FilterOut() {
			cFilterVal = cFilterVal | filterProcTreeOut
		}
	}
	if t.config.Filter.Follow {
		cFilterVal = cFilterVal | filterFollowEnabled
	}

	return cFilterVal
}

func (t *Tracee) populateBPFMaps() error {
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
		// Initialize map for global symbols of the kernel
		bpfKsymsMap, err := t.bpfModule.GetMap("ksymbols_map") // u32, u64
		if err != nil {
			return err
		}

		var reqKsyms []string
		for id := range t.events {
			event := events.Definitions.Get(id)
			reqKsyms = append(reqKsyms, event.Dependencies.KSymbols...)
		}

		kallsymsValues := initialization.LoadKallsymsValues(t.kernelSymbols, reqKsyms)

		initialization.SendKsymbolsToMap(bpfKsymsMap, kallsymsValues)
	}

	// Initialize kconfig variables (map used instead of relying in libbpf's .kconfig automated maps)
	// Note: this allows libbpf not to rely on the system kconfig file, tracee does the kconfig var identification job

	bpfKConfigMap, err := t.bpfModule.GetMap("kconfig_map") // u32, u32
	if err != nil {
		return err
	}

	kconfigValues, err := initialization.LoadKconfigValues(t.config.KernelConfig, t.config.Debug)
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

	// Initialize config map
	bpfConfigMap, err := t.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}

	cZero := uint32(0)
	configVal := make([]byte, 208)
	binary.LittleEndian.PutUint32(configVal[0:4], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(configVal[4:8], t.getOptionsConfig())
	binary.LittleEndian.PutUint32(configVal[8:12], t.getFiltersConfig())
	binary.LittleEndian.PutUint32(configVal[12:16], uint32(t.containers.GetCgroupV1HID()))
	binary.LittleEndian.PutUint64(configVal[16:24], t.config.Filter.UIDFilter.Less)
	binary.LittleEndian.PutUint64(configVal[24:32], t.config.Filter.UIDFilter.Greater)
	binary.LittleEndian.PutUint64(configVal[32:40], t.config.Filter.PIDFilter.Less)
	binary.LittleEndian.PutUint64(configVal[40:48], t.config.Filter.PIDFilter.Greater)
	binary.LittleEndian.PutUint64(configVal[48:56], t.config.Filter.MntNSFilter.Less)
	binary.LittleEndian.PutUint64(configVal[56:64], t.config.Filter.MntNSFilter.Greater)
	binary.LittleEndian.PutUint64(configVal[64:72], t.config.Filter.PidNSFilter.Less)
	binary.LittleEndian.PutUint64(configVal[72:80], t.config.Filter.PidNSFilter.Greater)
	// Next 128 bytes (1024 bits) are used for events_to_submit configuration
	// Set according to events chosen by the user
	for id, e := range t.events {
		if id >= 1024 {
			// we support up to 1024 events shared with bpf code
			continue
		}
		if e.submit {
			index := id / 8
			offset := id % 8
			configVal[80+index] = configVal[80+index] | (1 << offset)
		}
	}
	if err = bpfConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(&configVal[0])); err != nil {
		return err
	}

	errmap := make(map[string]error, 0)
	errmap["uid_filter"] = t.config.Filter.UIDFilter.InitBPF(t.bpfModule, "uid_filter")
	errmap["pid_filter"] = t.config.Filter.PIDFilter.InitBPF(t.bpfModule, "pid_filter")
	errmap["mnt_ns_filter"] = t.config.Filter.MntNSFilter.InitBPF(t.bpfModule, "mnt_ns_filter")
	errmap["pid_ns_filter"] = t.config.Filter.PidNSFilter.InitBPF(t.bpfModule, "pid_ns_filter")
	errmap["uts_ns_filter"] = t.config.Filter.UTSFilter.InitBPF(t.bpfModule, "uts_ns_filter")
	errmap["comm_filter"] = t.config.Filter.CommFilter.InitBPF(t.bpfModule, "comm_filter")
	errmap["cont_id_filter"] = t.config.Filter.ContIDFilter.InitBPF(t.bpfModule, t.containers, "cgroup_id_filter")

	for k, v := range errmap {
		if v != nil {
			return fmt.Errorf("error setting %v filter: %v", k, v)
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

	if len(t.netInfo.ifaces) > 0 {
		networkConfingMap, err := t.bpfModule.GetMap("network_config") // u32, int
		if err != nil {
			return err
		}
		for _, iface := range t.netInfo.ifaces {
			ifaceIdx := iface.Index
			ifaceConf := t.netInfo.ifacesConfig[iface.Name]
			if err := networkConfingMap.Update(unsafe.Pointer(&ifaceIdx), unsafe.Pointer(&ifaceConf)); err != nil {
				return err
			}

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
				if index > 10000 { // undefined syscalls (check arm64.go)
					return []events.TailCall{}, fmt.Errorf("cannot set tail call with invalid map index (over 10000)")
				}
			}
			tailCallStr := fmt.Sprint(tailCall)
			if !tailCallProgs[tailCallStr] {
				tailCalls = append(tailCalls, tailCall)
			}
			tailCallProgs[tailCallStr] = true
		}
		if def.Syscall && cfg.submit {
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

	// attach selected tracing events

	for tr := range t.events {
		event, ok := events.Definitions.GetSafe(tr)
		if !ok {
			continue
		}
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
		for _, dep := range event.Probes {
			err = t.probes.Attach(dep.Handle)
			if err != nil && dep.Required {
				// TODO: https://github.com/aquasecurity/tracee/issues/1787
				return fmt.Errorf("failed to attach required probe: %v", err)
			}
		}
	}

	// attach all tc programs to given interfaces

	for _, iface := range t.netInfo.ifaces {
		for _, tc := range []probes.Handle{
			probes.DefaultTcIngress,
			probes.DefaultTcEgress,
		} {
			err = t.probes.Attach(tc, iface)
			if err != nil {
				return err
			}
		}
	}

	// TODO: instead of manually attaching tc programs to given interfaces,
	// in a near future tc probes will be just events probeDependency and
	// attached to given interfaces (or all of them). If attached to all
	// existing interfaces, the tc programs will be constantly attached
	// to new network interface.

	return nil
}

func (t *Tracee) initBPF() error {
	var err error
	isCaptureNetSet := t.config.Capture.NetIfaces != nil
	isFilterNetSet := len(t.config.Filter.NetFilter.Interfaces()) != 0

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

	netEnabled := isCaptureNetSet || isFilterNetSet

	t.probes, err = probes.Init(t.bpfModule, netEnabled)
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

	err = t.config.Filter.ProcessTreeFilter.Set(t.bpfModule)
	if err != nil {
		return fmt.Errorf("error building process tree: %v", err)
	}

	// Initialize perf buffers
	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	t.eventsPerfMap, err = t.bpfModule.InitPerfBuf("events", t.eventsChannel, t.lostEvChannel, t.config.PerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	t.fileWrChannel = make(chan []byte, 1000)
	t.lostWrChannel = make(chan uint64)
	t.fileWrPerfMap, err = t.bpfModule.InitPerfBuf("file_writes", t.fileWrChannel, t.lostWrChannel, t.config.BlobPerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing file_writes perf map: %v", err)
	}

	t.netChannel = make(chan []byte, 1000)
	t.lostNetChannel = make(chan uint64)
	t.netPerfMap, err = t.bpfModule.InitPerfBuf("net_events", t.netChannel, t.lostNetChannel, t.config.BlobPerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing net perf map: %v", err)
	}

	return nil
}

func (t *Tracee) writeProfilerStats(wr io.Writer) error {
	b, err := json.MarshalIndent(t.profiledFiles, "", "  ")
	if err != nil {
		return err
	}

	_, err = wr.Write(b)

	return err
}

func (t *Tracee) getProcessCtx(hostTid uint32) (procinfo.ProcessCtx, error) {
	processCtx, err := t.procInfo.GetElement(int(hostTid))
	if err == nil {
		return processCtx, nil
	} else {
		processContextMap, err := t.bpfModule.GetMap("task_info_map")
		if err != nil {
			return processCtx, err
		}
		processCtxBpfMap, err := processContextMap.GetValue(unsafe.Pointer(&hostTid))
		if err != nil {
			return processCtx, err
		}
		processCtx, err = procinfo.ParseProcessContext(processCtxBpfMap, t.containers)
		t.procInfo.UpdateElement(int(hostTid), processCtx)
		return processCtx, err
	}
}

// Run starts the trace. it will run until ctx is cancelled
func (t *Tracee) Run(ctx gocontext.Context) error {
	t.invokeInitEvents()
	t.triggerSyscallsIntegrityCheck(trace.Event{})
	t.triggerSeqOpsIntegrityCheck(trace.Event{})
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	t.netPerfMap.Start()
	go t.processLostEvents()
	go t.handleEvents(ctx)
	go t.processFileWrites()
	go t.processNetEvents(ctx)
	t.running = true
	// block until ctx is cancelled elsewhere
	<-ctx.Done()
	t.eventsPerfMap.Stop()
	t.fileWrPerfMap.Stop()
	t.netPerfMap.Stop()
	// capture profiler stats
	if t.config.Capture.Profile {
		f, err := utils.CreateAt(t.outDir, "tracee.profile")
		if err != nil {
			return fmt.Errorf("unable to open tracee.profile for writing: %s", err)
		}

		// update SHA for all captured files
		t.updateFileSHA()

		if err := t.writeProfilerStats(f); err != nil {
			return fmt.Errorf("unable to write profiler output: %s", err)
		}
	}

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
	if t.probes != nil {
		err := t.probes.DetachAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to detach probes when closing tracee: %s", err)
		}
	}

	if t.bpfModule != nil {
		t.bpfModule.Close()
	}

	if t.containers != nil {
		err := t.containers.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to clean containers module when closing tracee: %s", err)
		}
	}
	t.running = false
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

func (t *Tracee) updateFileSHA() {
	for k, v := range t.profiledFiles {
		s := strings.Split(k, ".")
		exeName := strings.Split(s[1], ":")[0]
		filePath := fmt.Sprintf("%s.%d.%s", s[0], v.FirstExecutionTs, exeName)
		fileSHA, _ := t.computeOutFileHash(filePath)
		v.FileHash = fileSHA
		t.profiledFiles[k] = v
	}
}

func (t *Tracee) invokeInitEvents() {
	if t.events[events.InitNamespaces].emit {
		systemInfoEvent := events.InitNamespacesEvent()
		t.config.ChanEvents <- systemInfoEvent
		t.stats.EventCount.Increment()
	}
	if t.events[events.ExistingContainer].emit {
		for _, e := range events.ExistingContainersEvents(t.containers, t.config.ContainersEnrich) {
			t.config.ChanEvents <- e
			t.stats.EventCount.Increment()
		}
	}
}

func (t *Tracee) getTracedIfaceIdx(ifaceName string) (int, bool) {
	return t.config.Filter.NetFilter.Find(ifaceName)
}

func (t *Tracee) getCapturedIfaceIdx(ifaceName string) (int, bool) {
	if t.config.Capture.NetIfaces == nil {
		return -1, false
	}
	return t.config.Capture.NetIfaces.Find(ifaceName)
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

func (t *Tracee) updateKallsyms() error {
	kernelSymbols, err := helpers.NewKernelSymbolsMap()
	if err != nil {
		return err
	}
	if !initialization.ValidateKsymbolsTable(kernelSymbols) {
		return errors.New("invalid ksymbol table")
	}

	t.kernelSymbols = kernelSymbols
	return nil
}
