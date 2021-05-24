package tracee_engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/bucketscache"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/config"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/consts"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/event"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/filters"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/stats"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/streamers"
)

type TraceeEngine interface {
	Consume() (<-chan event.Event, error)
	Run() error
	Stats() *stats.Store
	Close()
}

type traceeEngine struct {
	config            config.Config
	eventsToTrace     map[int32]bool
	bpfModule         *bpf.Module
	DecParamName      [2]map[consts.ArgTag]string
	EncParamName      [2]map[string]consts.ArgTag
	ParamTypes        map[int32]map[string]string
	capturedFiles     map[string]int64
	writtenFiles      map[string]string
	pidsInMntns       bucketscache.BucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
	StackAddressesMap *bpf.BPFMap
	eventsPerfMap     *bpf.PerfBuffer
	fileWrPerfMap     *bpf.PerfBuffer
	eventsChannel     chan []byte
	fileWrChannel     chan []byte
	lostEvChannel     chan uint64
	lostWrChannel     chan uint64
	stats             stats.Store
	exportableChannel chan event.Event
}

func NewTraceeEngineMgr(cfg config.Config) (TraceeEngine, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	setEssential := func(id int32) {
		event := consts.EventsIDToEvent[id]
		event.EssentialEvent = true
		consts.EventsIDToEvent[id] = event
	}
	if cfg.Capture.Exec {
		setEssential(consts.SecurityBprmCheckEventID)
	}
	if cfg.Capture.FileWrite {
		setEssential(consts.VfsWriteEventID)
		setEssential(consts.VfsWritevEventID)
	}
	if cfg.SecurityAlerts || cfg.Capture.Mem {
		setEssential(consts.MmapEventID)
		setEssential(consts.MprotectEventID)
	}
	if cfg.Capture.Mem {
		setEssential(consts.MemProtAlertEventID)
	}
	t := &traceeEngine{
		config:            cfg,
		exportableChannel: make(chan event.Event, 1000),
	}
	t.eventsToTrace = make(map[int32]bool, len(t.config.Filter.EventsToTrace))
	for _, e := range t.config.Filter.EventsToTrace {
		// Map value is true iff events requested by the user
		t.eventsToTrace[e] = true
	}

	if t.eventsToTrace[consts.MagicWriteEventID] {
		setEssential(consts.VfsWriteEventID)
		setEssential(consts.VfsWritevEventID)
	}

	// Compile final list of events to trace including essential events
	for id, event := range consts.EventsIDToEvent {
		// If an essential event was not requested by the user, set its map value to false
		if event.EssentialEvent && !t.eventsToTrace[id] {
			t.eventsToTrace[id] = false
		}
	}

	t.DecParamName[0] = make(map[consts.ArgTag]string)
	t.EncParamName[0] = make(map[string]consts.ArgTag)
	t.DecParamName[1] = make(map[consts.ArgTag]string)
	t.EncParamName[1] = make(map[string]consts.ArgTag)
	t.ParamTypes = make(map[int32]map[string]string)

	for eventId, params := range consts.EventsIDToParams {
		t.ParamTypes[eventId] = make(map[string]string)
		for _, param := range params {
			t.ParamTypes[eventId][param.Name] = param.Type
		}
	}
	err = t.initBPF(cfg.BPFObjPath)
	if err != nil {
		t.Close()
		return nil, err
	}
	t.writtenFiles = make(map[string]string)
	t.capturedFiles = make(map[string]int64)
	//set a default value for config.maxPidsCache
	if t.config.MaxPidsCache == 0 {
		t.config.MaxPidsCache = 5
	}
	t.pidsInMntns.Init(t.config.MaxPidsCache)

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

	// Get refernce to stack trace addresses map
	StackAddressesMap, err := t.bpfModule.GetMap("stack_addresses")
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("error getting acces to 'stack_addresses' eBPF Map %v", err)
	}
	t.StackAddressesMap = StackAddressesMap
	return t, nil
}

func (t *traceeEngine) Stats() *stats.Store {
	return &t.stats
}

func (t *traceeEngine) Close() {
	if t.bpfModule != nil {
		t.bpfModule.Close()
	}
}

func (t *traceeEngine) Consume() (<-chan event.Event, error) {
	if t.exportableChannel == nil {
		return nil, fmt.Errorf("channel not ready to be consume")
	}
	return t.exportableChannel, nil
}

func (t *traceeEngine) initBPF(bpfObjectPath string) error {
	var err error

	t.bpfModule, err = bpf.NewModuleFromFile(bpfObjectPath)
	if err != nil {
		return err
	}

	// BPFLoadObject() automatically loads ALL BPF programs according to their section type, unless set otherwise
	// For every BPF program, we need to make sure that:
	// 1. We disable autoload if the program is not required by any event and is not essential
	// 2. The correct BPF program type is set
	for _, event := range consts.EventsIDToEvent {
		for _, probe := range event.Probes {
			prog, _ := t.bpfModule.GetProgram(probe.Fn)
			if prog == nil && probe.Attach == consts.SysCall {
				prog, _ = t.bpfModule.GetProgram(fmt.Sprintf("syscall__%s", probe.Fn))
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
	//
	err = t.bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	err = t.populateBPFMaps()
	if err != nil {
		return err
	}

	for e := range t.eventsToTrace {
		event, ok := consts.EventsIDToEvent[e]
		if !ok {
			continue
		}
		for _, probe := range event.Probes {
			if probe.Attach == consts.SysCall {
				// Already handled by raw_syscalls tracepoints
				continue
			}
			prog, err := t.bpfModule.GetProgram(probe.Fn)
			if err != nil {
				return fmt.Errorf("error getting program %s: %v", probe.Fn, err)
			}
			switch probe.Attach {
			case consts.Kprobe:
				_, err = prog.AttachKprobe(probe.Event)
			case consts.Kretprobe:
				_, err = prog.AttachKretprobe(probe.Event)
			case consts.Tracepoint:
				_, err = prog.AttachTracepoint(probe.Event)
			case consts.RawTracepoint:
				tpEvent := strings.Split(probe.Event, ":")[1]
				_, err = prog.AttachRawTracepoint(tpEvent)
			}
			if err != nil {
				return fmt.Errorf("error attaching event %s: %v", probe.Event, err)
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

	return nil
}

func (t *traceeEngine) setUintFilter(filter *filters.UintFilter, filterMapName string, configFilter consts.BpfConfig, lessIdx uint32) error {
	if !filter.Enabled {
		return nil
	}

	equalityFilter, err := t.bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		if filter.Is32Bit {
			err = equalityFilter.Update(uint32(filter.Equal[i]), consts.FilterEqual)
		} else {
			err = equalityFilter.Update(filter.Equal[i], consts.FilterEqual)
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		if filter.Is32Bit {
			err = equalityFilter.Update(uint32(filter.NotEqual[i]), consts.FilterNotEqual)
		} else {
			err = equalityFilter.Update(filter.NotEqual[i], consts.FilterNotEqual)
		}
		if err != nil {
			return err
		}
	}

	inequalityFilter, err := t.bpfModule.GetMap("inequality_filter")
	if err != nil {
		return err
	}

	err = inequalityFilter.Update(lessIdx, filter.Less)
	if err != nil {
		return err
	}
	err = inequalityFilter.Update(lessIdx+1, filter.Greater)
	if err != nil {
		return err
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map")
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.Greater == consts.GreaterNotSetUint && filter.Less == consts.LessNotSetUint {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterIn)
	} else {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterOut)
	}

	return nil
}

func (t *traceeEngine) setStringFilter(filter *filters.StringFilter, filterMapName string, configFilter consts.BpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	filterMap, err := t.bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		err = filterMap.Update([]byte(filter.Equal[i]), consts.FilterEqual)
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		err = filterMap.Update([]byte(filter.NotEqual[i]), consts.FilterNotEqual)
		if err != nil {
			return err
		}
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map")
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterIn)
	} else {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterOut)
	}

	return nil
}

func (t *traceeEngine) setBoolFilter(filter *filters.BoolFilter, configFilter consts.BpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map")
	if err != nil {
		return err
	}
	if filter.Value {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterIn)
	} else {
		bpfConfigMap.Update(uint32(configFilter), consts.FilterOut)
	}

	return nil
}

func (t *traceeEngine) initEventsParams() map[int32][]consts.EventParam {
	eventsParams := make(map[int32][]consts.EventParam)
	var seenNames [2]map[string]bool
	var ParamNameCounter [2]consts.ArgTag
	seenNames[0] = make(map[string]bool)
	ParamNameCounter[0] = consts.ArgTag(1)
	seenNames[1] = make(map[string]bool)
	ParamNameCounter[1] = consts.ArgTag(1)
	paramT := consts.NoneT
	for id, params := range consts.EventsIDToParams {
		for _, param := range params {
			switch param.Type {
			case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
				paramT = consts.IntT
			case "unsigned int", "u32":
				paramT = consts.UintT
			case "long":
				paramT = consts.LongT
			case "unsigned long", "u64":
				paramT = consts.UlongT
			case "off_t":
				paramT = consts.OffT
			case "mode_t":
				paramT = consts.ModeT
			case "dev_t":
				paramT = consts.DevT
			case "size_t":
				paramT = consts.SizeT
			case "void*", "const void*":
				paramT = consts.PointerT
			case "char*", "const char*":
				paramT = consts.StrT
			case "const char*const*", "const char**", "char**":
				paramT = consts.StrArrT
			case "const struct sockaddr*", "struct sockaddr*":
				paramT = consts.SockAddrT
			case "bytes":
				paramT = consts.BytesT
			default:
				// Default to pointer (printed as hex) for unsupported types
				paramT = consts.PointerT
			}

			// As the encoded parameter name is u8, it can hold up to 256 different names
			// To keep on low communication overhead, we don't change this to u16
			// Instead, use an array of enc/dec maps, where the key is modulus of the event id
			// This can easilly be expanded in the future if required
			if !seenNames[id%2][param.Name] {
				seenNames[id%2][param.Name] = true
				t.EncParamName[id%2][param.Name] = ParamNameCounter[id%2]
				t.DecParamName[id%2][ParamNameCounter[id%2]] = param.Name
				eventsParams[id] = append(eventsParams[id], consts.EventParam{EncType: paramT, EncName: ParamNameCounter[id%2]})
				ParamNameCounter[id%2]++
			} else {
				eventsParams[id] = append(eventsParams[id], consts.EventParam{EncType: paramT, EncName: t.EncParamName[id%2][param.Name]})
			}
		}
	}

	if len(seenNames[0]) > 255 || len(seenNames[1]) > 255 {
		panic("Too many argument names given")
	}

	return eventsParams
}
func (t *traceeEngine) populateBPFMaps() error {
	chosenEventsMap, _ := t.bpfModule.GetMap("chosen_events_map")
	for e, chosen := range t.eventsToTrace {
		// Set chosen events map according to events chosen by the user
		if chosen {
			chosenEventsMap.Update(e, boolToUInt32(true))
		}
	}

	sys32to64BPFMap, _ := t.bpfModule.GetMap("sys_32_to_64_map")
	for _, event := range consts.EventsIDToEvent {
		// Prepare 32bit to 64bit syscall number mapping
		sys32to64BPFMap.Update(event.ID32Bit, event.ID)
	}

	// Initialize config and pids maps
	bpfConfigMap, _ := t.bpfModule.GetMap("config_map")
	bpfConfigMap.Update(uint32(consts.ConfigDetectOrigSyscall), boolToUInt32(t.config.Output.DetectSyscall))
	bpfConfigMap.Update(uint32(consts.ConfigExecEnv), boolToUInt32(t.config.Output.ExecEnv))
	bpfConfigMap.Update(uint32(consts.ConfigStackAddresses), boolToUInt32(t.config.Output.StackAddresses))
	bpfConfigMap.Update(uint32(consts.ConfigCaptureFiles), boolToUInt32(t.config.Capture.FileWrite))
	bpfConfigMap.Update(uint32(consts.ConfigExtractDynCode), boolToUInt32(t.config.Capture.Mem))
	bpfConfigMap.Update(uint32(consts.ConfigTraceePid), uint32(os.Getpid()))
	bpfConfigMap.Update(uint32(consts.ConfigFollowFilter), boolToUInt32(t.config.Filter.Follow))

	// Initialize tail calls program array
	bpfProgArrayMap, _ := t.bpfModule.GetMap("prog_array")
	prog, err := t.bpfModule.GetProgram("trace_ret_vfs_write_tail")
	if err != nil {
		return fmt.Errorf("error getting BPF program trace_ret_vfs_write_tail: %v", err)
	}
	bpfProgArrayMap.Update(consts.TailVfsWrite, uint32(prog.GetFd()))

	prog, err = t.bpfModule.GetProgram("trace_ret_vfs_writev_tail")
	if err != nil {
		return fmt.Errorf("error getting BPF program trace_ret_vfs_writev_tail: %v", err)
	}
	bpfProgArrayMap.Update(consts.TailVfsWritev, uint32(prog.GetFd()))

	prog, err = t.bpfModule.GetProgram("send_bin")
	if err != nil {
		return fmt.Errorf("error getting BPF program send_bin: %v", err)
	}
	bpfProgArrayMap.Update(consts.TailSendBin, uint32(prog.GetFd()))

	// Set filters given by the user to filter file write events
	fileFilterMap, _ := t.bpfModule.GetMap("file_filter")
	for i := 0; i < len(t.config.Capture.FilterFileWrite); i++ {
		fileFilterMap.Update(uint32(i), []byte(t.config.Capture.FilterFileWrite[i]))
	}

	err = t.setUintFilter(t.config.Filter.UIDFilter, "uid_filter", consts.ConfigUIDFilter, consts.UidLess)
	if err != nil {
		return fmt.Errorf("error setting uid filter: %v", err)
	}

	err = t.setUintFilter(t.config.Filter.PIDFilter, "pid_filter", consts.ConfigPidFilter, consts.PidLess)
	if err != nil {
		return fmt.Errorf("error setting pid filter: %v", err)
	}

	err = t.setBoolFilter(t.config.Filter.NewPidFilter, consts.ConfigNewPidFilter)
	if err != nil {
		return fmt.Errorf("error setting pid=new filter: %v", err)
	}

	err = t.setUintFilter(t.config.Filter.MntNSFilter, "mnt_ns_filter", consts.ConfigMntNsFilter, consts.MntNsLess)
	if err != nil {
		return fmt.Errorf("error setting mntns filter: %v", err)
	}

	err = t.setUintFilter(t.config.Filter.PidNSFilter, "pid_ns_filter", consts.ConfigPidNsFilter, consts.PidNsLess)
	if err != nil {
		return fmt.Errorf("error setting pidns filter: %v", err)
	}

	err = t.setStringFilter(t.config.Filter.UTSFilter, "uts_ns_filter", consts.ConfigUTSNsFilter)
	if err != nil {
		return fmt.Errorf("error setting uts_ns filter: %v", err)
	}

	err = t.setStringFilter(t.config.Filter.CommFilter, "comm_filter", consts.ConfigCommFilter)
	if err != nil {
		return fmt.Errorf("error setting comm filter: %v", err)
	}

	err = t.setBoolFilter(t.config.Filter.ContFilter, consts.ConfigContFilter)
	if err != nil {
		return fmt.Errorf("error setting cont filter: %v", err)
	}

	err = t.setBoolFilter(t.config.Filter.NewContFilter, consts.ConfigNewContFilter)
	if err != nil {
		return fmt.Errorf("error setting container=new filter: %v", err)
	}

	stringStoreMap, _ := t.bpfModule.GetMap("string_store")
	stringStoreMap.Update(uint32(0), []byte("/dev/null"))

	eventsParams := t.initEventsParams()

	// After initializing event params, we can also initialize argument filters argTags
	for eventID, eventFilters := range t.config.Filter.ArgFilter.Filters {
		for argName, filter := range eventFilters {
			argTag, ok := t.EncParamName[eventID%2][argName]
			if !ok {
				return fmt.Errorf("event argument %s for event %d was not initialized correctly", argName, eventID)
			}
			filter.ArgTag = argTag
			eventFilters[argName] = filter
		}
	}

	sysEnterTailsBPFMap, _ := t.bpfModule.GetMap("sys_enter_tails")
	//sysExitTailsBPFMap := t.bpfModule.GetMap("sys_exit_tails")
	paramsTypesBPFMap, _ := t.bpfModule.GetMap("params_types_map")
	paramsNamesBPFMap, _ := t.bpfModule.GetMap("params_names_map")
	for e := range t.eventsToTrace {
		params := eventsParams[e]
		var paramsTypes uint64
		var paramsNames uint64
		for n, param := range params {
			paramsTypes = paramsTypes | (uint64(param.EncType) << (8 * n))
			paramsNames = paramsNames | (uint64(param.EncName) << (8 * n))
		}
		paramsTypesBPFMap.Update(e, paramsTypes)
		paramsNamesBPFMap.Update(e, paramsNames)

		if e == consts.ExecveEventID || e == consts.ExecveatEventID {
			event, ok := consts.EventsIDToEvent[e]
			if !ok {
				continue
			}

			probFnName := fmt.Sprintf("syscall__%s", event.Name)

			// execve functions require tail call on syscall enter as they perform extra work
			prog, err := t.bpfModule.GetProgram(probFnName)
			if err != nil {
				return fmt.Errorf("error loading BPF program %s: %v", probFnName, err)
			}
			sysEnterTailsBPFMap.Update(e, int32(prog.GetFd()))
		}
	}

	return nil
}
func (t *traceeEngine) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.LostEvCounter.Increment(int(lost))
	}
}

func (t *traceeEngine) decodeRawEvent(done <-chan struct{}) (<-chan consts.RawEvent, <-chan error, error) {
	out := make(chan consts.RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx consts.Context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				errc <- err
				continue
			}

			rawArgs := make(map[consts.ArgTag]interface{})
			argsTags := make([]consts.ArgTag, ctx.Argnum)
			for i := 0; i < int(ctx.Argnum); i++ {
				tag, val, err := readArgFromBuff(dataBuff)
				if err != nil {
					errc <- err
					continue
				}
				argsTags[i] = tag
				rawArgs[tag] = val
			}
			select {
			case out <- consts.RawEvent{ctx, rawArgs, argsTags}:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *traceeEngine) shouldProcessEvent(e consts.RawEvent) bool {
	if t.config.Filter.RetFilter.Enabled {
		if filter, ok := t.config.Filter.RetFilter.Filters[e.Ctx.EventID]; ok {
			retVal := e.Ctx.Retval
			match := false
			for _, f := range filter.Equal {
				if retVal == f {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if retVal == f {
					return false
				}
			}
			if (filter.Greater != consts.GreaterNotSetInt) && retVal <= filter.Greater {
				return false
			}
			if (filter.Less != consts.LessNotSetInt) && retVal >= filter.Less {
				return false
			}
		}
	}

	if t.config.Filter.ArgFilter.Enabled {
		for _, filter := range t.config.Filter.ArgFilter.Filters[e.Ctx.EventID] {
			argVal, ok := e.RawArgs[filter.ArgTag]
			if !ok {
				continue
			}
			// TODO: use type assertion instead of string convertion
			argValStr := fmt.Sprint(argVal)
			match := false
			for _, f := range filter.Equal {
				if argValStr == f || (f[len(f)-1] == '*' && strings.HasPrefix(argValStr, f[0:len(f)-1])) {
					match = true
					break
				}
			}
			if !match && len(filter.Equal) > 0 {
				return false
			}
			for _, f := range filter.NotEqual {
				if argValStr == f || (f[len(f)-1] == '*' && strings.HasPrefix(argValStr, f[0:len(f)-1])) {
					return false
				}
			}
		}
	}

	return true
}

func (t *traceeEngine) processEvent(ctx *consts.Context, args map[consts.ArgTag]interface{}) error {
	switch ctx.EventID {

	//capture written files
	case consts.VfsWriteEventID, consts.VfsWritevEventID:
		if t.config.Capture.FileWrite {
			filePath, ok := args[t.EncParamName[ctx.EventID%2]["pathname"]].(string)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}
			dev, ok := args[t.EncParamName[ctx.EventID%2]["dev"]].(uint32)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}
			inode, ok := args[t.EncParamName[ctx.EventID%2]["inode"]].(uint64)
			if !ok {
				return fmt.Errorf("error parsing vfs_write args")
			}

			// stop processing if write was already indexed
			fileName := fmt.Sprintf("%d/write.dev-%d.inode-%d", ctx.MntID, dev, inode)
			indexName, ok := t.writtenFiles[fileName]
			if ok && indexName == filePath {
				return nil
			}

			// index written file by original filepath
			t.writtenFiles[fileName] = filePath
		}

	case consts.SecurityBprmCheckEventID:

		//cache this pid by it's mnt ns
		if ctx.Pid == 1 {
			t.pidsInMntns.ForceAddBucketItem(ctx.MntID, ctx.HostPid)
		} else {
			t.pidsInMntns.AddBucketItem(ctx.MntID, ctx.HostPid)
		}

		//capture executed files
		if t.config.Capture.Exec {
			filePath, ok := args[t.EncParamName[ctx.EventID%2]["pathname"]].(string)
			if !ok {
				return fmt.Errorf("error parsing security_bprm_check args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath == "" || filePath[0] != '/' {
				return nil
			}

			destinationDirPath := filepath.Join(t.config.Capture.OutputPath, strconv.Itoa(int(ctx.MntID)))
			if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
				return err
			}
			destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", ctx.Ts, filepath.Base(filePath)))

			var err error
			// try to access the root fs via another process in the same mount namespace (since the current process might have already died)
			pids := t.pidsInMntns.GetBucket(ctx.MntID)
			for _, pid := range pids { // will break on success
				err = nil
				sourceFilePath := fmt.Sprintf("/proc/%s/root%s", strconv.Itoa(int(pid)), filePath)
				var sourceFileStat os.FileInfo
				sourceFileStat, err = os.Stat(sourceFilePath)
				if err != nil {
					//TODO: remove dead pid from cache
					continue
				}
				//don't capture same file twice unless it was modified
				sourceFileCtime := sourceFileStat.Sys().(*syscall.Stat_t).Ctim.Nano()
				capturedFileID := fmt.Sprintf("%d:%s", ctx.MntID, sourceFilePath)
				lastCtime, ok := t.capturedFiles[capturedFileID]
				if ok && lastCtime == sourceFileCtime {
					return nil
				}
				//capture
				err = CopyFileByPath(sourceFilePath, destinationFilePath)
				if err != nil {
					return err
				}
				//mark this file as captured
				t.capturedFiles[capturedFileID] = sourceFileCtime
				break
			}
			return err
		}
	}

	return nil
}

func (t *traceeEngine) processRawEvent(done <-chan struct{}, in <-chan consts.RawEvent) (<-chan consts.RawEvent, <-chan error, error) {
	out := make(chan consts.RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldProcessEvent(rawEvent) {
				continue
			}
			err := t.processEvent(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			select {
			case out <- rawEvent:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *traceeEngine) runEventPipeline(done <-chan struct{}) error {
	var errcList []<-chan error

	//Source pipeline stage.
	rawEventChan, errc, err := t.decodeRawEvent(done)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	processedEventChan, errc, err := t.processRawEvent(done, rawEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)
	errc, err = t.prepareEventForPrint(done, processedEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)
	// Pipeline started. Waiting for pipeline to complete
	return t.WaitForPipeline(errcList...)
	return nil
}

func (t *traceeEngine) handleError(err error) {
	t.stats.ErrorCounter.Increment()
	// TODO should be taken care by the broker
	//t.printer.Error(err)
}

// WaitForPipeline waits for results from all error channels.
func (t *traceeEngine) WaitForPipeline(errs ...<-chan error) error {
	errc := mergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// shouldPrintEvent decides whether or not the given event id should be printed to the output
func (t *traceeEngine) shouldPrintEvent(e consts.RawEvent) bool {
	// Only print events requested by the user
	if !t.eventsToTrace[e.Ctx.EventID] {
		return false
	}
	return true
}

func (t *traceeEngine) prepareArgsForPrint(ctx *consts.Context, args map[consts.ArgTag]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}
	switch ctx.EventID {
	case consts.SysEnterEventID, consts.SysExitEventID, consts.CapCapableEventID:
		//show syscall name instead of id
		if id, isInt32 := args[t.EncParamName[ctx.EventID%2]["syscall"]].(int32); isInt32 {
			if event, isKnown := consts.EventsIDToEvent[id]; isKnown {
				if event.Probes[0].Attach == consts.SysCall {
					args[t.EncParamName[ctx.EventID%2]["syscall"]] = event.Probes[0].Event
				}
			}
		}
		if ctx.EventID == consts.CapCapableEventID {
			if capability, isInt32 := args[t.EncParamName[ctx.EventID%2]["cap"]].(int32); isInt32 {
				args[t.EncParamName[ctx.EventID%2]["cap"]] = helpers.ParseCapability(capability)
			}
		}
	case consts.MmapEventID, consts.MprotectEventID, consts.PkeyMprotectEventID:
		if prot, isInt32 := args[t.EncParamName[ctx.EventID%2]["prot"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["prot"]] = helpers.ParseMemProt(uint32(prot))
		}
	case consts.PtraceEventID:
		if req, isInt64 := args[t.EncParamName[ctx.EventID%2]["request"]].(int64); isInt64 {
			args[t.EncParamName[ctx.EventID%2]["request"]] = helpers.ParsePtraceRequest(req)
		}
	case consts.PrctlEventID:
		if opt, isInt32 := args[t.EncParamName[ctx.EventID%2]["option"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["option"]] = helpers.ParsePrctlOption(opt)
		}
	case consts.SocketEventID:
		if dom, isInt32 := args[t.EncParamName[ctx.EventID%2]["domain"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["domain"]] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[t.EncParamName[ctx.EventID%2]["type"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["type"]] = helpers.ParseSocketType(uint32(typ))
		}
	case consts.SecuritySocketCreateEventID:
		if dom, isInt32 := args[t.EncParamName[ctx.EventID%2]["family"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["family"]] = helpers.ParseSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[t.EncParamName[ctx.EventID%2]["type"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["type"]] = helpers.ParseSocketType(uint32(typ))
		}
	case consts.ConnectEventID, consts.AcceptEventID, consts.Accept4EventID, consts.BindEventID, consts.GetsocknameEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.EventID%2]["addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.EventID%2]["addr"]] = s
		}
	case consts.SecuritySocketBindEventID, consts.SecuritySocketAcceptEventID, consts.SecuritySocketListenEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.EventID%2]["local_addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.EventID%2]["local_addr"]] = s
		}
	case consts.SecuritySocketConnectEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.EventID%2]["remote_addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.EventID%2]["remote_addr"]] = s
		}
	case consts.AccessEventID, consts.FaccessatEventID:
		if mode, isInt32 := args[t.EncParamName[ctx.EventID%2]["mode"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["mode"]] = helpers.ParseAccessMode(uint32(mode))
		}
	case consts.ExecveatEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.EventID%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = helpers.ParseExecFlags(uint32(flags))
		}
	case consts.OpenEventID, consts.OpenatEventID, consts.SecurityFileOpenEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.EventID%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = helpers.ParseOpenFlags(uint32(flags))
		}
	case consts.MknodEventID, consts.MknodatEventID, consts.ChmodEventID, consts.FchmodEventID, consts.FchmodatEventID:
		if mode, isUint32 := args[t.EncParamName[ctx.EventID%2]["mode"]].(uint32); isUint32 {
			args[t.EncParamName[ctx.EventID%2]["mode"]] = helpers.ParseInodeMode(mode)
		}
	case consts.MemProtAlertEventID:
		if alert, isAlert := args[t.EncParamName[ctx.EventID%2]["alert"]].(alert); isAlert {
			args[t.EncParamName[ctx.EventID%2]["alert"]] = printAlert(alert)
		}
	case consts.CloneEventID:
		if flags, isUint64 := args[t.EncParamName[ctx.EventID%2]["flags"]].(uint64); isUint64 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = helpers.ParseCloneFlags(flags)
		}
	case consts.SendtoEventID, consts.RecvfromEventID:
		addrTag := t.EncParamName[ctx.EventID%2]["dest_addr"]
		if ctx.EventID == consts.RecvfromEventID {
			addrTag = t.EncParamName[ctx.EventID%2]["src_addr"]
		}
		if sockAddr, isStrMap := args[addrTag].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[addrTag] = s
		}
	case consts.BpfEventID:
		if cmd, isInt32 := args[t.EncParamName[ctx.EventID%2]["cmd"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["cmd"]] = helpers.ParseBPFCmd(cmd)
		}
	}

	return nil
}

func (t *traceeEngine) prepareEventForPrint(done <-chan struct{}, in <-chan consts.RawEvent) (<-chan error, error) {
	//out := make(chan event.Event, 1000)
	errc := make(chan error, 1)
	go func() {
		defer close(t.exportableChannel)
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldPrintEvent(rawEvent) {
				continue
			}
			err := t.prepareArgsForPrint(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			args := make([]interface{}, rawEvent.Ctx.Argnum)
			argMetas := make([]event.ArgMeta, rawEvent.Ctx.Argnum)
			for i, tag := range rawEvent.ArgsTags {
				args[i] = rawEvent.RawArgs[tag]
				argName, ok := t.DecParamName[rawEvent.Ctx.EventID%2][tag]
				if ok {
					argMetas[i].Name = argName
				} else {
					errc <- fmt.Errorf("invalid arg tag for event %d", rawEvent.Ctx.EventID)
					continue
				}
				argType, ok := t.ParamTypes[rawEvent.Ctx.EventID][argName]
				if ok {
					argMetas[i].Type = argType
				} else {
					errc <- fmt.Errorf("invalid arg type for arg name %s of event %d", argName, rawEvent.Ctx.EventID)
					continue
				}
			}

			// Add stack trace if needed
			var StackAddresses []uint64
			if t.config.Output.StackAddresses {
				StackAddresses, _ = t.getStackAddresses(rawEvent.Ctx.StackID)
			}

			evt, err := streamers.NewEvent(rawEvent.Ctx, argMetas, args, StackAddresses)
			if err != nil {

				errc <- err
				continue
			}
			select {
			case t.exportableChannel <- evt:
			case <-done:
				return
			}
		}
	}()
	return errc, nil
}

func (t *traceeEngine) getStackAddresses(StackID uint32) ([]uint64, error) {
	StackAddresses := make([]uint64, consts.MaxStackDepth)
	stackFrameSize := (strconv.IntSize / 8)

	// Lookup the StackID in the map
	// The ID could have aged out of the Map, as it only holds a finite number of
	// Stack IDs in it's Map
	stackBytes, err := t.StackAddressesMap.GetValue(StackID)
	if err != nil {
		return StackAddresses[0:0], nil
	}

	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		StackAddresses[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		StackAddresses[stackCounter] = stackAddr
		stackCounter++
	}

	// Attempt to remove the ID from the map so we don't fill it up
	// But if this fails continue on
	_ = t.StackAddressesMap.DeleteKey(StackID)

	return StackAddresses[0:stackCounter], nil

}
func (t *traceeEngine) processFileWrites() {
	type chunkMeta struct {
		BinType  consts.BinType
		MntID    uint32
		Metadata [20]byte
		Size     int32
		Off      uint64
	}

	type vfsWriteMeta struct {
		DevID uint32
		Inode uint64
		Mode  uint32
		Pid   uint32
	}

	type mprotectWriteMeta struct {
		Ts uint64
	}

	const (
		S_IFMT uint32 = 0170000 // bit mask for the file type bit field

		S_IFSOCK uint32 = 0140000 // socket
		S_IFLNK  uint32 = 0120000 // symbolic link
		S_IFREG  uint32 = 0100000 // regular file
		S_IFBLK  uint32 = 0060000 // block device
		S_IFDIR  uint32 = 0040000 // directory
		S_IFCHR  uint32 = 0020000 // character device
		S_IFIFO  uint32 = 0010000 // FIFO
	)

	for {
		select {
		case dataRaw := <-t.fileWrChannel:
			if len(dataRaw) == 0 {
				continue
			}
			dataBuff := bytes.NewBuffer(dataRaw)
			var meta chunkMeta
			appendFile := false
			err := binary.Read(dataBuff, binary.LittleEndian, &meta)
			if err != nil {
				t.handleError(err)
				continue
			}

			if meta.Size <= 0 {
				t.handleError(fmt.Errorf("error in file writer: invalid chunk size: %d", meta.Size))
				continue
			}
			if dataBuff.Len() < int(meta.Size) {
				t.handleError(fmt.Errorf("error in file writer: chunk too large: %d", meta.Size))
				continue
			}

			pathname := path.Join(t.config.Capture.OutputPath, strconv.Itoa(int(meta.MntID)))
			if err := os.MkdirAll(pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuff := bytes.NewBuffer(meta.Metadata[:])
			if meta.BinType == consts.SendVfsWrite {
				var vfsMeta vfsWriteMeta
				err = binary.Read(metaBuff, binary.LittleEndian, &vfsMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				if vfsMeta.Mode&S_IFSOCK == S_IFSOCK || vfsMeta.Mode&S_IFCHR == S_IFCHR || vfsMeta.Mode&S_IFIFO == S_IFIFO {
					appendFile = true
				}
				if vfsMeta.Pid == 0 {
					filename = fmt.Sprintf("write.dev-%d.inode-%d", vfsMeta.DevID, vfsMeta.Inode)
				} else {
					filename = fmt.Sprintf("write.dev-%d.inode-%d.pid-%d", vfsMeta.DevID, vfsMeta.Inode, vfsMeta.Pid)
				}
			} else if meta.BinType == consts.SendMprotect {
				var mprotectMeta mprotectWriteMeta
				err = binary.Read(metaBuff, binary.LittleEndian, &mprotectMeta)
				if err != nil {
					t.handleError(err)
					continue
				}
				// note: size of buffer will determine maximum extracted file size! (as writes from kernel are immediate)
				filename = fmt.Sprintf("bin.%d", mprotectMeta.Ts)
			} else {
				t.handleError(fmt.Errorf("error in file writer: unknown binary type: %d", meta.BinType))
				continue
			}

			fullname := path.Join(pathname, filename)

			f, err := os.OpenFile(fullname, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				t.handleError(err)
				continue
			}
			if appendFile {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					f.Close()
					t.handleError(err)
					continue
				}
			} else {
				if _, err := f.Seek(int64(meta.Off), io.SeekStart); err != nil {
					f.Close()
					t.handleError(err)
					continue
				}
			}

			dataBytes, err := readByteSliceFromBuff(dataBuff, int(meta.Size))
			if err != nil {
				f.Close()
				t.handleError(err)
				continue
			}
			if _, err := f.Write(dataBytes); err != nil {
				f.Close()
				t.handleError(err)
				continue
			}
			if err := f.Close(); err != nil {
				t.handleError(err)
				continue
			}
		case lost := <-t.lostWrChannel:
			t.stats.LostWrCounter.Increment(int(lost))
		}
	}
}

func (t *traceeEngine) Run() error {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	go t.processLostEvents()
	go t.runEventPipeline(done)
	go t.processFileWrites()
	<-sig
	t.eventsPerfMap.Stop()
	t.fileWrPerfMap.Stop()

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
	close(done)
	t.Close()
	return nil
}
