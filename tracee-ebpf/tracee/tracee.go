package tracee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/userevents"
	"io"
	"io/ioutil"
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
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

// Config is a struct containing user defined configuration of tracee
type Config struct {
	Filter             *Filter
	Capture            *CaptureConfig
	Output             *OutputConfig
	PerfBufferSize     int
	BlobPerfBufferSize int
	SecurityAlerts     bool
	Debug              bool
	maxPidsCache       int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
	BTFObjPath         string
	BPFObjPath         string
	BPFObjBytes        []byte
	ChanEvents         chan external.Event
	ChanErrors         chan error
	ChanDone           chan struct{}
}

type Filter struct {
	EventsToTrace []int32
	UIDFilter     *UintFilter
	PIDFilter     *UintFilter
	NewPidFilter  *BoolFilter
	MntNSFilter   *UintFilter
	PidNSFilter   *UintFilter
	UTSFilter     *StringFilter
	CommFilter    *StringFilter
	ContFilter    *BoolFilter
	NewContFilter *BoolFilter
	RetFilter     *RetFilter
	ArgFilter     *ArgFilter
	Follow        bool
}

type UintFilter struct {
	Equal    []uint64
	NotEqual []uint64
	Greater  uint64
	Less     uint64
	Is32Bit  bool
	Enabled  bool
}

type IntFilter struct {
	Equal    []int64
	NotEqual []int64
	Greater  int64
	Less     int64
	Is32Bit  bool
	Enabled  bool
}

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

type BoolFilter struct {
	Value   bool
	Enabled bool
}

type RetFilter struct {
	Filters map[int32]IntFilter
	Enabled bool
}

type ArgFilter struct {
	Filters map[int32]map[string]ArgFilterVal // key to the first map is event id, and to the second map the argument name
	Enabled bool
}

type ArgFilterVal struct {
	Equal    []string
	NotEqual []string
}

type CaptureConfig struct {
	OutputPath      string
	FileWrite       bool
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
		if _, ok := EventsIDToEvent[e]; !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
	}
	for eventID, eventFilters := range tc.Filter.ArgFilter.Filters {
		for argName := range eventFilters {
			eventParams, ok := EventsIDToParams[eventID]
			if !ok {
				return fmt.Errorf("invalid argument filter event id: %d", eventID)
			}
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
	profiledFiles     map[string]profilerInfo
	writtenFiles      map[string]string
	mntNsFirstPid     map[uint32]uint32
	DecParamName      [2]map[argTag]string
	EncParamName      [2]map[string]argTag
	ParamTypes        map[int32]map[string]string
	pidsInMntns       bucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
	StackAddressesMap *bpf.BPFMap
	tcProbe           []netProbe
	pcapWriter        *pcapgo.NgWriter
	pcapFile          *os.File
	ngIfacesIndex     map[int]int
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
		event := EventsIDToEvent[id]
		event.EssentialEvent = true
		EventsIDToEvent[id] = event
	}
	if cfg.Capture.Exec {
		setEssential(SecurityBprmCheckEventID)
	}
	if cfg.Capture.FileWrite {
		setEssential(VfsWriteEventID)
		setEssential(VfsWritevEventID)
	}
	if cfg.SecurityAlerts || cfg.Capture.Mem {
		setEssential(MmapEventID)
		setEssential(MprotectEventID)
	}
	if cfg.Capture.Mem {
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

	// Compile final list of events to trace including essential events
	for id, event := range EventsIDToEvent {
		// If an essential event was not requested by the user, set its map value to false
		if event.EssentialEvent && !t.eventsToTrace[id] {
			t.eventsToTrace[id] = false
		}
	}

	t.DecParamName[0] = make(map[argTag]string)
	t.EncParamName[0] = make(map[string]argTag)
	t.DecParamName[1] = make(map[argTag]string)
	t.EncParamName[1] = make(map[string]argTag)
	t.ParamTypes = make(map[int32]map[string]string)

	for eventId, params := range EventsIDToParams {
		t.ParamTypes[eventId] = make(map[string]string)
		for _, param := range params {
			t.ParamTypes[eventId][param.Name] = param.Type
		}
	}

	err = t.initBPF()
	if err != nil {
		t.Close()
		return nil, err
	}

	t.writtenFiles = make(map[string]string)
	t.capturedFiles = make(map[string]int64)
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
	// Todo: tracee.pid should be in a known constant location. /var/run is probably a better choice
	err = ioutil.WriteFile(path.Join(t.config.Capture.OutputPath, "tracee.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0640)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("error creating readiness file: %v", err)
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

// UnameRelease gets the version string of the current running kernel
func UnameRelease() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}
	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}
	ver := string(buf[:])
	if i := strings.Index(ver, "\x00"); i != -1 {
		ver = ver[:i]
	}
	return ver
}

func kernelIsAtLeast(verMajor, verMinor int) (bool, error) {
	ver := UnameRelease()
	if ver == "" {
		return false, fmt.Errorf("could not determine current release")
	}
	verSplit := strings.Split(ver, ".")
	if len(verSplit) < 2 {
		return false, fmt.Errorf("invalid version returned by uname")
	}
	major, err := strconv.Atoi(verSplit[0])
	if err != nil {
		return false, fmt.Errorf("invalid major number: %s", verSplit[0])
	}
	minor, err := strconv.Atoi(verSplit[1])
	if err != nil {
		return false, fmt.Errorf("invalid minor number: %s", verSplit[1])
	}
	if ((major == verMajor) && (minor >= verMinor)) || (major > verMajor) {
		return true, nil
	}
	return false, nil
}

type eventParam struct {
	encType argType
	encName argTag
}

func (t *Tracee) initEventsParams() map[int32][]eventParam {
	eventsParams := make(map[int32][]eventParam)
	var seenNames [2]map[string]bool
	var ParamNameCounter [2]argTag
	seenNames[0] = make(map[string]bool)
	ParamNameCounter[0] = argTag(1)
	seenNames[1] = make(map[string]bool)
	ParamNameCounter[1] = argTag(1)
	paramT := noneT
	for id, params := range EventsIDToParams {
		for _, param := range params {
			switch param.Type {
			case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
				paramT = intT
			case "unsigned int", "u32":
				paramT = uintT
			case "long":
				paramT = longT
			case "unsigned long", "u64":
				paramT = ulongT
			case "off_t":
				paramT = offT
			case "mode_t":
				paramT = modeT
			case "dev_t":
				paramT = devT
			case "size_t":
				paramT = sizeT
			case "void*", "const void*":
				paramT = pointerT
			case "char*", "const char*":
				paramT = strT
			case "const char*const*", "const char**", "char**":
				paramT = strArrT
			case "const struct sockaddr*", "struct sockaddr*":
				paramT = sockAddrT
			case "bytes":
				paramT = bytesT
			case "int[2]":
				paramT = intArr2T
			default:
				// Default to pointer (printed as hex) for unsupported types
				paramT = pointerT
			}

			// As the encoded parameter name is u8, it can hold up to 256 different names
			// To keep on low communication overhead, we don't change this to u16
			// Instead, use an array of enc/dec maps, where the key is modulus of the event id
			// This can easilly be expanded in the future if required
			if !seenNames[id%2][param.Name] {
				seenNames[id%2][param.Name] = true
				t.EncParamName[id%2][param.Name] = ParamNameCounter[id%2]
				t.DecParamName[id%2][ParamNameCounter[id%2]] = param.Name
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: ParamNameCounter[id%2]})
				ParamNameCounter[id%2]++
			} else {
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: t.EncParamName[id%2][param.Name]})
			}
		}
	}

	if len(seenNames[0]) > 255 || len(seenNames[1]) > 255 {
		panic("Too many argument names given")
	}

	return eventsParams
}

func (t *Tracee) setUintFilter(filter *UintFilter, filterMapName string, configFilter bpfConfig, lessIdx uint32) error {
	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, u32
	// 2. pid_filter        u32, u32
	// 3. mnt_ns_filter     u64, u32
	// 4. pid_ns_filter     u64, u32
	equalityFilter, err := t.bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		if filter.Is32Bit {
			EqualU32 := uint32(filter.Equal[i])
			err = equalityFilter.Update(unsafe.Pointer(&EqualU32), unsafe.Pointer(&filterEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.Equal[i]), unsafe.Pointer(&filterEqualU32))
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		if filter.Is32Bit {
			NotEqualU32 := uint32(filter.NotEqual[i])
			err = equalityFilter.Update(unsafe.Pointer(&NotEqualU32), unsafe.Pointer(&filterNotEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.NotEqual[i]), unsafe.Pointer(&filterNotEqualU32))
		}
		if err != nil {
			return err
		}
	}

	filterLessU32 := uint32(filter.Less)
	filterGreaterU32 := uint32(filter.Greater)

	// inequalityFilter filters events by some uint field either by < or >
	inequalityFilter, err := t.bpfModule.GetMap("inequality_filter") // u32, u64
	if err != nil {
		return err
	}
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdx), unsafe.Pointer(&filterLessU32)); err != nil {
		return err
	}
	lessIdxPlus := uint32(lessIdx + 1)
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdxPlus), unsafe.Pointer(&filterGreaterU32)); err != nil {
		return err
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.Greater == GreaterNotSetUint && filter.Less == LessNotSetUint {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
}

func (t *Tracee) setStringFilter(filter *StringFilter, filterMapName string, configFilter bpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// 1. uts_ns_filter     string[MAX_STR_FILTER_SIZE], u32    // filter events by uts namespace name
	// 2. comm_filter       string[MAX_STR_FILTER_SIZE], u32    // filter events by command name
	filterMap, err := t.bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		filterEqualBytes := []byte(filter.Equal[i])
		if err = filterMap.Update(unsafe.Pointer(&filterEqualBytes[0]), unsafe.Pointer(&filterEqualU32)); err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		filterNotEqualBytes := []byte(filter.NotEqual[i])
		if err = filterMap.Update(unsafe.Pointer(&filterNotEqualBytes[0]), unsafe.Pointer(&filterNotEqualU32)); err != nil {
			return err
		}
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
}

func (t *Tracee) setBoolFilter(filter *BoolFilter, configFilter bpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if filter.Value {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
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
	for _, event := range EventsIDToEvent {
		ID32BitU32 := uint32(event.ID32Bit) // ID32Bit is int32
		IDU32 := uint32(event.ID)           // ID is int32
		if err := sys32to64BPFMap.Update(unsafe.Pointer(&ID32BitU32), unsafe.Pointer(&IDU32)); err != nil {
			return err
		}
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
	cEDC := uint32(configExtractDynCode)
	cFF := uint32(configFollowFilter)
	cDN := uint32(configDebugNet)

	thisPid := uint32(os.Getpid())
	cDOSval := boolToUInt32(t.config.Output.DetectSyscall)
	cEVval := boolToUInt32(t.config.Output.ExecEnv)
	cSAval := boolToUInt32(t.config.Output.StackAddresses)
	cCFval := boolToUInt32(t.config.Capture.FileWrite)
	cEDCval := boolToUInt32(t.config.Capture.Mem)
	cFFval := boolToUInt32(t.config.Filter.Follow)
	cDNval := boolToUInt32(t.config.Debug)

	errs := make([]error, 0)
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cTP), unsafe.Pointer(&thisPid)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cDOS), unsafe.Pointer(&cDOSval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cEV), unsafe.Pointer(&cEVval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cSA), unsafe.Pointer(&cSAval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cCF), unsafe.Pointer(&cCFval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cEDC), unsafe.Pointer(&cEDCval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cFF), unsafe.Pointer(&cFFval)))
	errs = append(errs, bpfConfigMap.Update(unsafe.Pointer(&cDN), unsafe.Pointer(&cDNval)))
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	// Initialize pid_to_cont_id_map if tracing containers
	c := InitContainers()
	if err := c.Populate(); err != nil {
		return err
	}
	bpfPidToContIdMap, _ := t.bpfModule.GetMap("pid_to_cont_id_map")
	for _, contId := range c.GetContainers() {
		for _, pid := range c.GetPids(contId) {
			if t.config.Debug {
				fmt.Println("Running container =", contId, "pid =", pid)
			}
			contIdBytes := []byte(contId)
			err = bpfPidToContIdMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&contIdBytes[0]))
			if err != nil {
				return err
			}
		}
	}

	// Initialize tail calls program array
	errs = make([]error, 0)
	errs = append(errs, t.initTailCall(tailVfsWrite, "prog_array", "trace_ret_vfs_write_tail"))
	errs = append(errs, t.initTailCall(tailVfsWritev, "prog_array", "trace_ret_vfs_writev_tail"))
	errs = append(errs, t.initTailCall(tailSendBin, "prog_array", "send_bin"))
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
	errmap["uid_filter"] = t.setUintFilter(t.config.Filter.UIDFilter, "uid_filter", configUIDFilter, uidLess)
	errmap["pid_filter"] = t.setUintFilter(t.config.Filter.PIDFilter, "pid_filter", configPidFilter, pidLess)
	errmap["pid=new_filter"] = t.setBoolFilter(t.config.Filter.NewPidFilter, configNewPidFilter)
	errmap["mnt_ns_filter"] = t.setUintFilter(t.config.Filter.MntNSFilter, "mnt_ns_filter", configMntNsFilter, mntNsLess)
	errmap["pid_ns_filter"] = t.setUintFilter(t.config.Filter.PidNSFilter, "pid_ns_filter", configPidNsFilter, pidNsLess)
	errmap["uts_ns_filter"] = t.setStringFilter(t.config.Filter.UTSFilter, "uts_ns_filter", configUTSNsFilter)
	errmap["comm_filter"] = t.setStringFilter(t.config.Filter.CommFilter, "comm_filter", configCommFilter)
	errmap["cont_filter"] = t.setBoolFilter(t.config.Filter.ContFilter, configContFilter)
	errmap["cont=new_filter"] = t.setBoolFilter(t.config.Filter.NewContFilter, configNewContFilter)
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

	eventsParams := t.initEventsParams()

	paramsTypesBPFMap, err := t.bpfModule.GetMap("params_types_map") // u32, u64
	if err != nil {
		return err
	}
	paramsNamesBPFMap, err := t.bpfModule.GetMap("params_names_map") // u32, u64
	if err != nil {
		return err
	}
	for e := range t.eventsToTrace {
		eU32 := uint32(e) // e is int32
		params := eventsParams[e]
		var paramsTypes uint64
		var paramsNames uint64
		for n, param := range params {
			paramsTypes = paramsTypes | (uint64(param.encType) << (8 * n))
			paramsNames = paramsNames | (uint64(param.encName) << (8 * n))
		}
		if err := paramsTypesBPFMap.Update(unsafe.Pointer(&eU32), unsafe.Pointer(&paramsTypes)); err != nil {
			return err
		}
		if err := paramsNamesBPFMap.Update(unsafe.Pointer(&eU32), unsafe.Pointer(&paramsNames)); err != nil {
			return err
		}
		if e == ExecveEventID || e == ExecveatEventID {
			event, ok := EventsIDToEvent[e]
			if !ok {
				continue
			}
			// execve functions require tail call on syscall enter as they perform extra work
			probFnName := fmt.Sprintf("syscall__%s", event.Name)
			err = t.initTailCall(eU32, "sys_enter_tails", probFnName)
			if err != nil {
				return err
			}
			// err = t.initTailCall(uint32(e), "sys_exit_tails", probFnName) // if ever needed
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

	t.bpfModule, err = bpf.NewModuleFromBufferBtf(t.config.BTFObjPath, t.config.BPFObjBytes, t.config.BPFObjPath)
	if err != nil {
		return err
	}

	// BPFLoadObject() automatically loads ALL BPF programs according to their section type, unless set otherwise
	// For every BPF program, we need to make sure that:
	// 1. We disable autoload if the program is not required by any event and is not essential
	// 2. The correct BPF program type is set
	for _, event := range EventsIDToEvent {
		for _, probe := range event.Probes {
			prog, _ := t.bpfModule.GetProgram(probe.fn)
			if prog == nil && probe.attach == sysCall {
				prog, _ = t.bpfModule.GetProgram(fmt.Sprintf("syscall__%s", probe.fn))
			}
			if prog == nil {
				continue
			}
			if _, ok := t.eventsToTrace[event.ID]; !ok {
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
		event, ok := EventsIDToEvent[e]
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
				_, err = prog.AttachTracepoint(probe.event)
			case rawTracepoint:
				tpEvent := strings.Split(probe.event, ":")[1]
				_, err = prog.AttachRawTracepoint(tpEvent)
			}
			if err != nil {
				return fmt.Errorf("error attaching event %s: %v", probe.event, err)
			}
		}
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
	t.invokeSystemInfoEvent()
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	t.netPerfMap.Start()
	go t.processLostEvents()
	go t.runEventPipeline(t.config.ChanDone)
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

func getFileHash(fileName string) string {
	f, _ := os.Open(fileName)
	if f != nil {
		defer f.Close()
		h := sha256.New()
		_, _ = io.Copy(h, f)
		return hex.EncodeToString(h.Sum(nil))
	}
	return ""
}

func (t *Tracee) updateFileSHA() {
	for k, v := range t.profiledFiles {
		s := strings.Split(k, ".")
		exeName := strings.Split(s[1], ":")[0]
		filePath := fmt.Sprintf("%s.%d.%s", s[0], v.FirstExecutionTs, exeName)
		fileSHA := getFileHash(filePath)
		v.FileHash = fileSHA
		t.profiledFiles[k] = v
	}
}

// shouldPrintEvent decides whether or not the given event id should be printed to the output
func (t *Tracee) shouldEmitEvent(e RawEvent) bool {
	// Only print events requested by the user
	if !t.eventsToTrace[e.Ctx.EventID] {
		return false
	}
	return true
}

func (t *Tracee) prepareArgs(ctx *context, args map[string]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}
	switch ctx.EventID {
	case SysEnterEventID, SysExitEventID, CapCapableEventID, CommitCredsEventID, SecurityFileOpenEventID:
		//show syscall name instead of id
		if id, isInt32 := args["syscall"].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args["syscall"] = event.Probes[0].event
				}
			}
		}
		if ctx.EventID == CapCapableEventID {
			if capability, isInt32 := args["cap"].(int32); isInt32 {
				args["cap"] = helpers.ParseCapability(capability)
			}
		}
		if ctx.EventID == SecurityFileOpenEventID {
			if flags, isInt32 := args["flags"].(int32); isInt32 {
				args["flags"] = helpers.ParseOpenFlags(uint32(flags))
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args["prot"].(int32); isInt32 {
			args["prot"] = helpers.ParseMemProt(uint32(prot))
		}
	case PtraceEventID:
		if req, isInt64 := args["request"].(int64); isInt64 {
			args["request"] = helpers.ParsePtraceRequest(req)
		}
	case PrctlEventID:
		if opt, isInt32 := args["option"].(int32); isInt32 {
			args["option"] = helpers.ParsePrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args["domain"].(int32); isInt32 {
			args["domain"] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args["type"].(int32); isInt32 {
			args["type"] = helpers.ParseSocketType(uint32(typ))
		}
	case SecuritySocketCreateEventID:
		if dom, isInt32 := args["family"].(int32); isInt32 {
			args["family"] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args["type"].(int32); isInt32 {
			args["type"] = helpers.ParseSocketType(uint32(typ))
		}
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args["addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["addr"] = s
		}
	case SecuritySocketBindEventID, SecuritySocketAcceptEventID, SecuritySocketListenEventID:
		if sockAddr, isStrMap := args["local_addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["local_addr"] = s
		}
	case SecuritySocketConnectEventID:
		if sockAddr, isStrMap := args["remote_addr"].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args["remote_addr"] = s
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args["mode"].(int32); isInt32 {
			args["mode"] = helpers.ParseAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args["flags"].(int32); isInt32 {
			args["flags"] = helpers.ParseExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID:
		if flags, isInt32 := args["flags"].(int32); isInt32 {
			args["flags"] = helpers.ParseOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args["mode"].(uint32); isUint32 {
			args["mode"] = helpers.ParseInodeMode(mode)
		}
	case SecurityInodeMknodEventID:
		if mode, isUint16 := args["mode"].(uint16); isUint16 {
			args["mode"] = helpers.ParseInodeMode(uint32(mode))
		}
	case MemProtAlertEventID:
		if alert, isAlert := args["alert"].(alert); isAlert {
			args["alert"] = PrintAlert(alert)
		}
	case CloneEventID:
		if flags, isUint64 := args["flags"].(uint64); isUint64 {
			args["flags"] = helpers.ParseCloneFlags(flags)
		}
	case SendtoEventID, RecvfromEventID:
		addrType := "dest_addr"
		if ctx.EventID == RecvfromEventID {
			addrType = "src_addr"
		}
		if sockAddr, isStrMap := args[addrType].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[addrType] = s
		}
	case BpfEventID:
		if cmd, isInt32 := args["cmd"].(int32); isInt32 {
			args["cmd"] = helpers.ParseBPFCmd(cmd)
		}
	}

	return nil
}

func (t *Tracee) invokeSystemInfoEvent() {
	if t.eventsToTrace[SystemInfoEventID] {
		systemInfoEvent, _ := userevents.CreateSystemInfoEvent()
		t.printer.Print(systemInfoEvent)
	}
}
