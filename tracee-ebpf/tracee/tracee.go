package tracee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/bucketscache"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/sys/unix"
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	Filter             *Filter
	Capture            *CaptureConfig
	Output             *OutputConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	Debug              bool
	maxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath         string
	BPFObjPath         string
	BPFObjBytes        []byte
	KernelConfig       *helpers.KernelConfig
	ChanEvents         chan external.Event
	ChanErrors         chan error
	ChanDone           chan struct{}
}

type CaptureConfig struct {
	OutputPath      string
	FileWrite       bool
	Module          bool
	FilterFileWrite []string
	Exec            bool
	Mem             bool
	Profile         bool
	NetIfaces       []string
}

type OutputConfig struct {
	StackAddresses bool
	DetectSyscall  bool
	ExecEnv        bool
	RelativeTime   bool
	ExecHash       bool
	ParseArguments bool
}

type netProbe struct {
	ingressHook *bpf.TcHook
	egressHook  *bpf.TcHook
}

// Validate does static validation of the configuration
func (tc Config) Validate() error {
	if tc.Filter == nil || tc.Filter.EventsToTrace == nil {
		return fmt.Errorf("Filter or EventsToTrace is nil")
	}

	for _, e := range tc.Filter.EventsToTrace {
		if _, ok := EventsDefinitions[e]; !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
	}
	for eventID, eventFilters := range tc.Filter.ArgFilter.Filters {
		for argName := range eventFilters {
			eventDefinition, ok := EventsDefinitions[eventID]
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

	if tc.ChanDone == nil {
		return errors.New("nil done channel")
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

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config            Config
	eventsToTrace     map[int32]bool
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
	stats             statsStore
	capturedFiles     map[string]int64
	fileHashes        *lru.Cache
	profiledFiles     map[string]profilerInfo
	writtenFiles      map[string]string
	mntNsFirstPid     map[uint32]uint32
	pidsInMntns       bucketscache.BucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
	StackAddressesMap *bpf.BPFMap
	tcProbe           []netProbe
	pcapWriter        *pcapgo.NgWriter
	pcapFile          *os.File
	ngIfacesIndex     map[int]int
	containers        *containers.Containers
}

type counter int32

func (c *counter) Increment(amount ...int) {
	sum := 1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum + a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}

type statsStore struct {
	eventCounter  counter
	errorCounter  counter
	lostEvCounter counter
	lostWrCounter counter
	lostNtCounter counter
}

func (t *Tracee) GetStats() external.Stats {
	var stats external.Stats

	stats.EventCount = int(t.stats.eventCounter)
	stats.ErrorCount = int(t.stats.errorCounter)
	stats.LostEvCount = int(t.stats.lostEvCounter)
	stats.LostWrCount = int(t.stats.lostWrCounter)
	stats.LostNtCount = int(t.stats.lostNtCounter)

	return stats
}

// New creates a new Tracee instance based on a given valid Config
func New(cfg Config) (*Tracee, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	setEssential := func(id int32) {
		event := EventsDefinitions[id]
		event.EssentialEvent = true
		EventsDefinitions[id] = event
	}
	if cfg.Capture.Exec {
		setEssential(SchedProcessExecEventID)
	}
	if cfg.Capture.FileWrite {
		setEssential(VfsWriteEventID)
		setEssential(VfsWritevEventID)
	}
	if cfg.Capture.Module {
		setEssential(SecurityPostReadFileEventID)
		setEssential(InitModuleEventID)
	}
	if cfg.Capture.Mem {
		setEssential(MmapEventID)
		setEssential(MprotectEventID)
		setEssential(MemProtAlertEventID)
	}

	if cfg.Capture.NetIfaces != nil || cfg.Debug {
		setEssential(SecuritySocketBindEventID)
	}

	// Tracee bpf code uses monotonic clock as event timestamp.
	// Get current monotonic clock so we can calculate event timestamps relative to it.
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	startTime := ts.Nano()
	// Calculate the boot time using the monotonic time (since this is the clock we're using as a timestamp)
	// Note: this is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

	// create tracee
	t := &Tracee{
		config:    cfg,
		startTime: uint64(startTime),
		bootTime:  uint64(bootTime),
	}

	t.eventsToTrace = make(map[int32]bool, len(t.config.Filter.EventsToTrace))
	for _, e := range t.config.Filter.EventsToTrace {
		// Map value is true iff events requested by the user
		t.eventsToTrace[e] = true
	}

	if t.eventsToTrace[MagicWriteEventID] {
		setEssential(VfsWriteEventID)
		setEssential(VfsWritevEventID)
	}

	if t.eventsToTrace[MemProtAlertEventID] {
		setEssential(MmapEventID)
		setEssential(MprotectEventID)
	}

	if t.eventsToTrace[SocketDupEventID] {
		setEssential(DupEventID)
		setEssential(Dup2EventID)
		setEssential(Dup3EventID)
	}

	// Compile final list of events to trace including essential events
	for id, event := range EventsDefinitions {
		// If an essential event was not requested by the user, set its map value to false
		if event.EssentialEvent && !t.eventsToTrace[id] {
			t.eventsToTrace[id] = false
		}
	}

	c := containers.InitContainers()
	if err := c.Populate(); err != nil {
		return nil, fmt.Errorf("error initializing containers: %v", err)
	}
	t.containers = c

	err = t.initBPF()
	if err != nil {
		t.Close()
		return nil, err
	}

	t.writtenFiles = make(map[string]string)
	t.capturedFiles = make(map[string]int64)
	t.fileHashes, err = lru.New(1024)
	if err != nil {
		t.Close()
		return nil, err
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
		return nil, fmt.Errorf("error creating output path: %v", err)
	}

	if t.config.Capture.NetIfaces != nil {
		pcapFile, err := os.Create(path.Join(t.config.Capture.OutputPath, "capture.pcap"))
		if err != nil {
			return nil, fmt.Errorf("error creating pcap file: %v", err)
		}
		t.pcapFile = pcapFile

		t.ngIfacesIndex = make(map[int]int)
		for idx, iface := range t.config.Capture.NetIfaces {
			netIface, err := net.InterfaceByName(iface)
			if err != nil {
				return nil, fmt.Errorf("invalid network interface: %s", iface)
			}
			// Map real network interface index to NgInterface index
			t.ngIfacesIndex[netIface.Index] = idx
		}

		ngIface := pcapgo.NgInterface{
			Name:       t.config.Capture.NetIfaces[0],
			Comment:    "tracee tc capture",
			Filter:     "",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		}

		pcapWriter, err := pcapgo.NewNgWriterInterface(t.pcapFile, ngIface, pcapgo.NgWriterOptions{})
		if err != nil {
			return nil, err
		}

		for _, iface := range t.config.Capture.NetIfaces[1:] {
			ngIface = pcapgo.NgInterface{
				Name:       iface,
				Comment:    "tracee tc capture",
				Filter:     "",
				LinkType:   layers.LinkTypeEthernet,
				SnapLength: uint32(math.MaxUint16),
			}

			_, err := pcapWriter.AddInterface(ngIface)
			if err != nil {
				return nil, err
			}
		}

		// Flush the header
		err = pcapWriter.Flush()
		if err != nil {
			return nil, err
		}
		t.pcapWriter = pcapWriter
	}

	// Get refernce to stack trace addresses map
	StackAddressesMap, err := t.bpfModule.GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("error getting acces to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = StackAddressesMap

	return t, nil
}

// Initialize tail calls program array
func (t *Tracee) initTailCall(tailNum uint32, mapName string, progName string) error {

	bpfMap, err := t.bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}
	bpfProg, err := t.bpfModule.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("could not get BPF program "+progName+": %v", err)
	}
	fd := bpfProg.GetFd()
	if fd < 0 {
		return fmt.Errorf("could not get BPF program FD for "+progName+": %v", err)
	}
	err = bpfMap.Update(unsafe.Pointer(&tailNum), unsafe.Pointer(&fd))

	return err
}

// bpfConfig is an enum that include various configurations that can be passed to bpf code
// config should match defined values in ebpf code
type bpfConfig uint32

const (
	configDetectOrigSyscall bpfConfig = iota + 1
	configExecEnv
	configCaptureFiles
	configExtractDynCode
	configTraceePid
	configStackAddresses
	configUIDFilter
	configMntNsFilter
	configPidNsFilter
	configUTSNsFilter
	configCommFilter
	configPidFilter
	configContFilter
	configFollowFilter
	configNewPidFilter
	configNewContFilter
	configDebugNet
	configProcTreeFilter
	configCaptureModules
	configCgroupV1
)

// Custom KernelConfigOption's to extend kernel_config helper support
// Add here all kconfig variables used within tracee.bpf.c
const (
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER helpers.KernelConfigOption = iota + helpers.CUSTOM_OPTION_START
)

// an enum that specifies the index of a function to be used in a bpf tail call
// tail function indexes should match defined values in ebpf code
const (
	tailVfsWrite uint32 = iota
	tailVfsWritev
	tailSendBin
	tailSendBinTP
)

func (t *Tracee) populateBPFMaps() error {

	// Set chosen events map according to events chosen by the user
	chosenEventsMap, err := t.bpfModule.GetMap("chosen_events_map") // u32, u32
	if err != nil {
		return err
	}
	for e, chosen := range t.eventsToTrace {
		if chosen {
			eU32 := uint32(e) // e is int32
			trueU32 := uint32(1)
			if err := chosenEventsMap.Update(unsafe.Pointer(&eU32), unsafe.Pointer(&trueU32)); err != nil {
				return err
			}
		}
	}

	// Prepare 32bit to 64bit syscall number mapping
	sys32to64BPFMap, err := t.bpfModule.GetMap("sys_32_to_64_map") // u32, u32
	if err != nil {
		return err
	}
	for id, event := range EventsDefinitions {
		ID32BitU32 := uint32(event.ID32Bit) // ID32Bit is int32
		IDU32 := uint32(id)                 // ID is int32
		if err := sys32to64BPFMap.Update(unsafe.Pointer(&ID32BitU32), unsafe.Pointer(&IDU32)); err != nil {
			return err
		}
	}

	// Initialize kconfig variables (map used instead of relying in libbpf's .kconfig automated maps)
	// Note: this allows libbpf not to rely on the system kconfig file, tracee does the kconfig var identification job

	bpfKConfigMap, err := t.bpfModule.GetMap("kconfig_map") // u32, u32
	if err != nil {
		return err
	}

	// add here all kconfig variables used within tracee.bpf.c
	var value helpers.KernelConfigOptionValue
	key := CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	keyString := "CONFIG_ARCH_HAS_SYSCALL_WRAPPER"
	if err = t.config.KernelConfig.AddCustomKernelConfig(key, keyString); err != nil {
		return err
	}

	// re-load kconfig and get just added kconfig option values
	if err = t.config.KernelConfig.LoadKernelConfig(); err != nil { // invalid kconfig file: assume values then
		if t.config.Debug {
			fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
		}
		value = helpers.BUILTIN // assume CONFIG_ARCH_HAS_SYSCALL_WRAPPER is a BUILTIN option
	} else {
		value = t.config.KernelConfig.GetValue(key) // undefined, builtin OR module
	}

	err = bpfKConfigMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		return err
	}

	// Initialize config and pids maps

	bpfConfigMap, err := t.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}

	cTP := uint32(configTraceePid)
	cDOS := uint32(configDetectOrigSyscall)
	cEV := uint32(configExecEnv)
	cSA := uint32(configStackAddresses)
	cCF := uint32(configCaptureFiles)
	cCM := uint32(configCaptureModules)
	cEDC := uint32(configExtractDynCode)
	cFF := uint32(configFollowFilter)
	cDN := uint32(configDebugNet)
	cCG1 := uint32(configCgroupV1)

	thisPid := uint32(os.Getpid())
	cDOSval := boolToUInt32(t.config.Output.DetectSyscall)
	cEVval := boolToUInt32(t.config.Output.ExecEnv)
	cSAval := boolToUInt32(t.config.Output.StackAddresses)
	cCFval := boolToUInt32(t.config.Capture.FileWrite)
	cCMval := boolToUInt32(t.config.Capture.Module)
	cEDCval := boolToUInt32(t.config.Capture.Mem)
	cFFval := boolToUInt32(t.config.Filter.Follow)
	cDNval := boolToUInt32(t.config.Debug)
	cCG1val := boolToUInt32(t.containers.IsCgroupV1())

	errs := make([]error, 0)
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cTP), unsafe.Pointer(&thisPid)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cDOS), unsafe.Pointer(&cDOSval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cEV), unsafe.Pointer(&cEVval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cSA), unsafe.Pointer(&cSAval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cCF), unsafe.Pointer(&cCFval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cCM), unsafe.Pointer(&cCMval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cEDC), unsafe.Pointer(&cEDCval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cFF), unsafe.Pointer(&cFFval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cDN), unsafe.Pointer(&cDNval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cCG1), unsafe.Pointer(&cCG1val)))
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	// Populate containers_map with existing containers
	t.containers.PopulateBpfMap(t.bpfModule, "containers_map")

	// Initialize tail calls program array
	errs = make([]error, 0)
	errs = append(errs, t.initTailCall(tailVfsWrite, "prog_array", "trace_ret_vfs_write_tail"))
	errs = append(errs, t.initTailCall(tailVfsWritev, "prog_array", "trace_ret_vfs_writev_tail"))
	errs = append(errs, t.initTailCall(tailSendBin, "prog_array", "send_bin"))
	errs = append(errs, t.initTailCall(tailSendBinTP, "prog_array_tp", "send_bin_tp"))
	for _, e := range errs {
		if e != nil {
			return e
		}
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

	errmap := make(map[string]error, 0)
	errmap["uid_filter"] = t.config.Filter.UIDFilter.Set(t.bpfModule, "uid_filter", configUIDFilter, uidLess)
	errmap["pid_filter"] = t.config.Filter.PIDFilter.Set(t.bpfModule, "pid_filter", configPidFilter, pidLess)
	errmap["pid=new_filter"] = t.config.Filter.NewPidFilter.Set(t.bpfModule, configNewPidFilter)
	errmap["mnt_ns_filter"] = t.config.Filter.MntNSFilter.Set(t.bpfModule, "mnt_ns_filter", configMntNsFilter, mntNsLess)
	errmap["pid_ns_filter"] = t.config.Filter.PidNSFilter.Set(t.bpfModule, "pid_ns_filter", configPidNsFilter, pidNsLess)
	errmap["uts_ns_filter"] = t.config.Filter.UTSFilter.Set(t.bpfModule, "uts_ns_filter", configUTSNsFilter)
	errmap["comm_filter"] = t.config.Filter.CommFilter.Set(t.bpfModule, "comm_filter", configCommFilter)
	errmap["cont_filter"] = t.config.Filter.ContFilter.Set(t.bpfModule, configContFilter)
	errmap["cont=new_filter"] = t.config.Filter.NewContFilter.Set(t.bpfModule, configNewContFilter)
	for k, v := range errmap {
		if v != nil {
			return fmt.Errorf("error setting %v filter: %v", k, v)
		}
	}

	stringStoreMap, err := t.bpfModule.GetMap("string_store") // []string[MAX_PATH_PREF_SIZE]
	if err != nil {
		return err
	}
	zero := uint32(0)
	null := []byte("/dev/null")
	err = stringStoreMap.Update(unsafe.Pointer(&zero), unsafe.Pointer(&null[0]))
	if err != nil {
		return err
	}

	eventsParams := make(map[int32][]argType)
	for id, eventDefinition := range EventsDefinitions {
		params := eventDefinition.Params
		for _, param := range params {
			eventsParams[id] = append(eventsParams[id], getParamType(param.Type))
		}
	}

	paramsTypesBPFMap, err := t.bpfModule.GetMap("params_types_map") // u32, u64
	if err != nil {
		return err
	}
	for e := range t.eventsToTrace {
		eU32 := uint32(e) // e is int32
		params := eventsParams[e]
		var paramsTypes uint64
		for n, paramType := range params {
			paramsTypes = paramsTypes | (uint64(paramType) << (8 * n))
		}
		if err := paramsTypesBPFMap.Update(unsafe.Pointer(&eU32), unsafe.Pointer(&paramsTypes)); err != nil {
			return err
		}

		// some functions require tail call on syscall enter/exit as they perform extra work
		if e == ExecveEventID || e == ExecveatEventID || e == InitModuleEventID {
			event, ok := EventsDefinitions[e]
			if !ok {
				continue
			}
			probFnName := fmt.Sprintf("syscall__%s", event.Name)
			err = t.initTailCall(eU32, "sys_enter_tails", probFnName)
			if err != nil {
				return err
			}
		} else if e == DupEventID || e == Dup2EventID || e == Dup3EventID {
			if err = t.initTailCall(eU32, "sys_exit_tails", "sys_dup_exit_tail"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t *Tracee) attachTcProg(ifaceName string, attachPoint bpf.TcAttachPoint, progName string) (*bpf.TcHook, error) {
	hook := t.bpfModule.TcHookInit()
	err := hook.SetInterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to set tc hook interface: %v", err)
	}
	hook.SetAttachPoint(attachPoint)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			return nil, fmt.Errorf("tc hook create: %v", err)
		}
	}
	prog, _ := t.bpfModule.GetProgram(progName)
	if prog == nil {
		return nil, fmt.Errorf("couldn't find tc program %s", progName)
	}
	var tcOpts bpf.TcOpts
	tcOpts.ProgFd = int(prog.GetFd())
	err = hook.Attach(&tcOpts)
	if err != nil {
		return nil, fmt.Errorf("tc attach: %v", err)
	}

	return hook, nil
}

func (t *Tracee) attachNetProbes() error {
	prog, _ := t.bpfModule.GetProgram("trace_udp_sendmsg")
	if prog == nil {
		return fmt.Errorf("couldn't find trace_udp_sendmsg program")
	}
	_, err := prog.AttachKprobe("udp_sendmsg")
	if err != nil {
		return fmt.Errorf("error attaching event udp_sendmsg: %v", err)
	}

	prog, _ = t.bpfModule.GetProgram("trace_udp_disconnect")
	if prog == nil {
		return fmt.Errorf("couldn't find trace_udp_disconnect program")
	}
	_, err = prog.AttachKprobe("__udp_disconnect")
	if err != nil {
		return fmt.Errorf("error attaching event __udp_disconnect: %v", err)
	}

	prog, _ = t.bpfModule.GetProgram("trace_udp_destroy_sock")
	if prog == nil {
		return fmt.Errorf("couldn't find trace_udp_destroy_sock program")
	}
	_, err = prog.AttachKprobe("udp_destroy_sock")
	if err != nil {
		return fmt.Errorf("error attaching event udp_destroy_sock: %v", err)
	}

	prog, _ = t.bpfModule.GetProgram("trace_udpv6_destroy_sock")
	if prog == nil {
		return fmt.Errorf("couldn't find trace_udpv6_destroy_sock program")
	}
	_, err = prog.AttachKprobe("udpv6_destroy_sock")
	if err != nil {
		return fmt.Errorf("error attaching event udpv6_destroy_sock: %v", err)
	}

	prog, _ = t.bpfModule.GetProgram("tracepoint__inet_sock_set_state")
	if prog == nil {
		return fmt.Errorf("couldn't find tracepoint__inet_sock_set_state program")
	}
	_, err = prog.AttachRawTracepoint("inet_sock_set_state")
	if err != nil {
		return fmt.Errorf("error attaching event sock:inet_sock_set_state: %v", err)
	}

	prog, _ = t.bpfModule.GetProgram("trace_tcp_connect")
	if prog == nil {
		return fmt.Errorf("couldn't find trace_tcp_connect program")
	}
	_, err = prog.AttachKprobe("tcp_connect")
	if err != nil {
		return fmt.Errorf("error attaching event tcp_connect: %v", err)
	}

	return nil
}

func (t *Tracee) initBPF() error {
	var err error

	newModuleArgs := bpf.NewModuleArgs{
		KConfigFilePath: t.config.KernelConfig.GetKernelConfigFilePath(),
		BTFObjPath:      t.config.BTFObjPath,
		BPFObjBuff:      t.config.BPFObjBytes,
		BPFObjName:      t.config.BPFObjPath,
	}

	t.bpfModule, err = bpf.NewModuleFromBufferArgs(newModuleArgs)
	if err != nil {
		return err
	}

	// BPFLoadObject() automatically loads ALL BPF programs according to their section type, unless set otherwise
	// For every BPF program, we need to make sure that:
	// 1. We disable autoload if the program is not required by any event and is not essential
	// 2. The correct BPF program type is set
	for id, event := range EventsDefinitions {
		for _, probe := range event.Probes {
			prog, _ := t.bpfModule.GetProgram(probe.fn)
			if prog == nil && probe.attach == sysCall {
				prog, _ = t.bpfModule.GetProgram(fmt.Sprintf("syscall__%s", probe.fn))
			}
			if prog == nil {
				continue
			}
			if _, ok := t.eventsToTrace[id]; !ok {
				// This event is not being traced - set its respective program(s) "autoload" to false
				err = prog.SetAutoload(false)
				if err != nil {
					return err
				}
				continue
			}
		}
	}

	if t.config.Capture.NetIfaces == nil && !t.config.Debug {
		// SecuritySocketBindEventID is set as an essentialEvent if 'capture net' or 'debug' were chosen by the user.
		networkProbes := []string{"tc_ingress", "tc_egress", "trace_udp_sendmsg", "trace_udp_disconnect", "trace_udp_destroy_sock", "trace_udpv6_destroy_sock", "tracepoint__inet_sock_set_state"}
		for _, progName := range networkProbes {
			prog, _ := t.bpfModule.GetProgram(progName)
			if prog == nil {
				return fmt.Errorf("couldn't find %s program", progName)
			}
			err = prog.SetAutoload(false)
			if err != nil {
				return err
			}
		}
	}

	err = t.bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	err = t.populateBPFMaps()
	if err != nil {
		return err
	}

	if t.config.Capture.NetIfaces != nil || t.config.Debug {
		for _, iface := range t.config.Capture.NetIfaces {
			ingressHook, err := t.attachTcProg(iface, bpf.BPFTcIngress, "tc_ingress")
			if err != nil {
				return err
			}

			egressHook, err := t.attachTcProg(iface, bpf.BPFTcEgress, "tc_egress")
			if err != nil {
				return err
			}

			tcProbe := netProbe{
				ingressHook: ingressHook,
				egressHook:  egressHook,
			}
			t.tcProbe = append(t.tcProbe, tcProbe)
		}

		if err = t.attachNetProbes(); err != nil {
			return err
		}
	}

	for e := range t.eventsToTrace {
		event, ok := EventsDefinitions[e]
		if !ok {
			continue
		}
		for _, probe := range event.Probes {
			if probe.attach == sysCall {
				// Already handled by raw_syscalls tracepoints
				continue
			}
			prog, err := t.bpfModule.GetProgram(probe.fn)
			if err != nil {
				return fmt.Errorf("error getting program %s: %v", probe.fn, err)
			}
			switch probe.attach {
			case kprobe:
				_, err = prog.AttachKprobe(probe.event)
			case kretprobe:
				_, err = prog.AttachKretprobe(probe.event)
			case tracepoint:
				tpEvent := strings.Split(probe.event, ":")
				if len(tpEvent) != 2 {
					err = fmt.Errorf("tracepoint must be in 'category:name' format")
				} else {
					_, err = prog.AttachTracepoint(probe.event, probe.event)
				}
			case rawTracepoint:
				tpEvent := strings.Split(probe.event, ":")[1]
				_, err = prog.AttachRawTracepoint(tpEvent)
			}
			if err != nil {
				return fmt.Errorf("error attaching event %s: %v", probe.event, err)
			}
		}
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
	if err != nil {
		return err
	}
	return nil
}

// Run starts the trace. it will run until interrupted
func (t *Tracee) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	t.invokeInitNamespacesEvent()
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	t.netPerfMap.Start()
	go t.processLostEvents()
	go t.handleEvents(t.config.ChanDone)
	go t.processFileWrites()
	go t.processNetEvents()
	<-sig
	t.eventsPerfMap.Stop()
	t.fileWrPerfMap.Stop()
	t.netPerfMap.Stop()
	// capture profiler stats
	if t.config.Capture.Profile {
		f, err := os.Create(filepath.Join(t.config.Capture.OutputPath, "tracee.profile"))
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
		destinationFilePath := filepath.Join(t.config.Capture.OutputPath, "written_files")
		f, err := os.OpenFile(destinationFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

	// Signal pipeline that Tracee exits by closing the done channel
	close(t.config.ChanDone)
	t.Close()
	return nil
}

// Close cleans up created resources
func (t *Tracee) Close() {
	for _, tcProbe := range t.tcProbe {
		// First, delete filters we created
		tcProbe.ingressHook.Destroy()
		tcProbe.egressHook.Destroy()

		// Todo: Delete the qdisc only if no other filters are installed on it.
		// There is currently a bug with the libbpf tc API that doesn't allow us to perform this check:
		// https://lore.kernel.org/bpf/CAMy7=ZULTCoSCcjxw=MdhaKmNM9DXKc=t7QScf9smKKUB+L_fQ@mail.gmail.com/T/#t
		tcProbe.ingressHook.SetAttachPoint(bpf.BPFTcIngressEgress)
		tcProbe.ingressHook.Destroy()
	}

	if t.bpfModule != nil {
		t.bpfModule.Close()
	}
}

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

func computeFileHash(fileName string) (string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
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
		fileSHA, _ := computeFileHash(filePath)
		v.FileHash = fileSHA
		t.profiledFiles[k] = v
	}
}

func (t *Tracee) invokeInitNamespacesEvent() {
	if t.eventsToTrace[InitNamespacesEventID] {
		systemInfoEvent, _ := CreateInitNamespacesEvent()
		t.config.ChanEvents <- systemInfoEvent
	}
}
