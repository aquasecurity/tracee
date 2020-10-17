package tracee

import (
	"bytes"
	"encoding/base64"
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
	"sync/atomic"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

// TraceeConfig is a struct containing user defined configuration of tracee
type TraceeConfig struct {
	EventsToTrace         []int32
	Mode                  uint32
	PidsToTrace           []int
	DetectOriginalSyscall bool
	ShowExecEnv           bool
	OutputFormat          string
	PerfBufferSize        int
	BlobPerfBufferSize    int
	OutputPath            string
	CaptureWrite          bool
	CaptureExec           bool
	CaptureMem            bool
	FilterFileWrite       []string
	SecurityAlerts        bool
	EventsFile            *os.File
	ErrorsFile            *os.File
	maxPidsCache          int // maximum number of pids to cache per mnt ns (in Tracee.pidsInMntns)
}

// Validate does static validation of the configuration
func (tc TraceeConfig) Validate() error {
	if tc.EventsToTrace == nil {
		return fmt.Errorf("eventsToTrace is nil")
	}
	if tc.OutputFormat != "table" && tc.OutputFormat != "table-verbose" && tc.OutputFormat != "json" && tc.OutputFormat != "gob" {
		return fmt.Errorf("unrecognized output format: %s", tc.OutputFormat)
	}
	for _, e := range tc.EventsToTrace {
		event, ok := EventsIDToEvent[e]
		if !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
		if event.Name == "reserved" {
			return fmt.Errorf("event is not implemented: %s", event.Name)
		}

	}
	if (tc.PerfBufferSize & (tc.PerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if (tc.BlobPerfBufferSize & (tc.BlobPerfBufferSize - 1)) != 0 {
		return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	}
	if len(tc.FilterFileWrite) > 3 {
		return fmt.Errorf("too many file-write filters given")
	}
	for _, filter := range tc.FilterFileWrite {
		if len(filter) > 64 {
			return fmt.Errorf("The length of a path filter is limited to 64 characters: %s", filter)
		}
	}
	return nil
}

// This var is supposed to be injected *at build time* with the contents of the ebpf c program
var ebpfProgramBase64Injected string

func getEBPFProgram() (string, error) {
	// if there's a local file, use it
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	ebpfFilePath := filepath.Join(filepath.Dir(exePath), "./event_monitor_ebpf.c")
	_, err = os.Stat(ebpfFilePath)
	if !os.IsNotExist(err) {
		p, err := ioutil.ReadFile(ebpfFilePath)
		return string(p), err
	}
	// if there's no local file, try injected variable
	if ebpfProgramBase64Injected != "" {
		p, err := base64.StdEncoding.DecodeString(ebpfProgramBase64Injected)
		if err != nil {
			return "", err
		}
		return string(p), nil
	}

	return "", fmt.Errorf("could not find ebpf program")
}

// Tracee traces system calls and system events using eBPF
type Tracee struct {
	config        TraceeConfig
	eventsToTrace map[int32]bool
	bpfModule     *bpf.Module
	eventsPerfMap *bpf.PerfMap
	fileWrPerfMap *bpf.PerfMap
	eventsChannel chan []byte
	fileWrChannel chan []byte
	lostEvChannel chan uint64
	lostWrChannel chan uint64
	printer       eventPrinter
	stats         statsStore
	capturedFiles map[string]int64
	mntNsFirstPid map[uint32]uint32
	DecParamName  [2]map[argTag]string
	EncParamName  [2]map[string]argTag
	pidsInMntns   bucketsCache //record the first n PIDs (host) in each mount namespace, for internal usage
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
}

// New creates a new Tracee instance based on a given valid TraceeConfig
func New(cfg TraceeConfig) (*Tracee, error) {
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
	if cfg.CaptureExec {
		setEssential(SecurityBprmCheckEventID)
	}
	if cfg.CaptureWrite {
		setEssential(VfsWriteEventID)
	}
	if cfg.SecurityAlerts || cfg.CaptureMem {
		setEssential(MmapEventID)
		setEssential(MprotectEventID)
	}
	if cfg.CaptureMem {
		setEssential(MemProtAlertEventID)
	}
	// create tracee
	t := &Tracee{
		config: cfg,
	}
	ContainerMode := (t.config.Mode == ModeContainerNew)
	t.printer = newEventPrinter(t.config.OutputFormat, ContainerMode, t.config.EventsFile, t.config.ErrorsFile)
	t.eventsToTrace = make(map[int32]bool, len(t.config.EventsToTrace))
	for _, e := range t.config.EventsToTrace {
		// Map value is true iff events requested by the user
		t.eventsToTrace[e] = true
	}

	t.DecParamName[0] = make(map[argTag]string)
	t.EncParamName[0] = make(map[string]argTag)
	t.DecParamName[1] = make(map[argTag]string)
	t.EncParamName[1] = make(map[string]argTag)

	p, err := getEBPFProgram()
	if err != nil {
		return nil, err
	}
	err = t.initBPF(p)
	if err != nil {
		t.Close()
		return nil, err
	}

	t.capturedFiles = make(map[string]int64)
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

	if err := os.MkdirAll(t.config.OutputPath, 0755); err != nil {
		return nil, fmt.Errorf("error creating output path: %v", err)
	}
	err = ioutil.WriteFile(path.Join(t.config.OutputPath, "tracee.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0640)
	if err != nil {
		return nil, fmt.Errorf("error creating readiness file: %v", err)
	}
	return t, nil
}

type bucketsCache struct {
	buckets     map[uint32][]uint32
	bucketLimit int
	Null        uint32
}

func (c *bucketsCache) Init(bucketLimit int) {
	c.bucketLimit = bucketLimit
	c.buckets = make(map[uint32][]uint32)
	c.Null = 0
}

func (c *bucketsCache) GetBucket(key uint32) []uint32 {
	return c.buckets[key]
}

func (c *bucketsCache) GetBucketItem(key uint32, index int) uint32 {
	b, exists := c.buckets[key]
	if !exists {
		return c.Null
	}
	if index >= len(b) {
		return c.Null
	}
	return b[index]
}

func (c *bucketsCache) AddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, false)
}

func (c *bucketsCache) ForceAddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, true)
}

func (c *bucketsCache) addBucketItem(key uint32, value uint32, force bool) {
	b, exists := c.buckets[key]
	if !exists {
		c.buckets[key] = make([]uint32, 0, c.bucketLimit)
		b = c.buckets[key]
	}
	if len(b) >= c.bucketLimit {
		if force {
			b[0] = value
		} else {
			return
		}
	} else {
		c.buckets[key] = append(b, value)
	}
}

func supportRawTP() (bool, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false, err
	}
	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}
	ver := string(buf[:])
	if i := strings.Index(ver, "\x00"); i != -1 {
		ver = ver[:i]
	}
	ver_split := strings.Split(ver, ".")
	if len(ver_split) < 2 {
		return false, fmt.Errorf("invalid version returned by uname")
	}
	major, err := strconv.Atoi(ver_split[0])
	if err != nil {
		return false, fmt.Errorf("invalid major number: %s", ver_split[0])
	}
	minor, err := strconv.Atoi(ver_split[1])
	if err != nil {
		return false, fmt.Errorf("invalid minor number: %s", ver_split[1])
	}
	if ((major == 4) && (minor >= 17)) || (major > 4) {
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
			switch param.pType {
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
			default:
				// Default to pointer (printed as hex) for unsupported types
				paramT = pointerT
			}

			// As the encoded parameter name is u8, it can hold up to 256 different names
			// To keep on low communication overhead, we don't change this to u16
			// Instead, use an array of enc/dec maps, where the key is modulus of the event id
			// This can easilly be expanded in the future if required
			if !seenNames[id%2][param.pName] {
				seenNames[id%2][param.pName] = true
				t.EncParamName[id%2][param.pName] = ParamNameCounter[id%2]
				t.DecParamName[id%2][ParamNameCounter[id%2]] = param.pName
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: ParamNameCounter[id%2]})
				ParamNameCounter[id%2]++
			} else {
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: t.EncParamName[id%2][param.pName]})
			}
		}
	}

	if len(seenNames[0]) > 255 || len(seenNames[1]) > 255 {
		panic("Too many argument names given")
	}

	return eventsParams
}

func (t *Tracee) initBPF(ebpfProgram string) error {
	var err error

	t.bpfModule = bpf.NewModule(ebpfProgram, []string{})

	chosenEvents := bpf.NewTable(t.bpfModule.TableId("chosen_events_map"), t.bpfModule)
	key := make([]byte, 4)
	leaf := make([]byte, 4)
	for e, _ := range t.eventsToTrace {
		// Set chosen events map according to events chosen by the user
		binary.LittleEndian.PutUint32(key, uint32(e))
		binary.LittleEndian.PutUint32(leaf, boolToUInt32(true))
		chosenEvents.Set(key, leaf)
	}

	sys32to64BPFTable := bpf.NewTable(t.bpfModule.TableId("sys_32_to_64_map"), t.bpfModule)
	for id, event := range EventsIDToEvent {
		// Prepare 32bit to 64bit syscall number mapping
		binary.LittleEndian.PutUint32(key, uint32(event.ID32Bit))
		binary.LittleEndian.PutUint32(leaf, uint32(event.ID))
		sys32to64BPFTable.Set(key, leaf)

		// Compile final list of events to trace including essential events
		// If an essential event was not requested by the user, set its map value to false
		if event.EssentialEvent && !t.eventsToTrace[id] {
			t.eventsToTrace[id] = false
		}
	}

	eventsParams := t.initEventsParams()

	supportRawTracepoints, err := supportRawTP()
	if err != nil {
		return fmt.Errorf("Failed to find kernel version: %v", err)
	}
	sysEnterTailsBPFTable := bpf.NewTable(t.bpfModule.TableId("sys_enter_tails"), t.bpfModule)
	//sysExitTailsBPFTable := bpf.NewTable(t.bpfModule.TableId("sys_exit_tails"), t.bpfModule)
	paramsTypesBPFTable := bpf.NewTable(t.bpfModule.TableId("params_types_map"), t.bpfModule)
	paramsNamesBPFTable := bpf.NewTable(t.bpfModule.TableId("params_names_map"), t.bpfModule)
	for e, _ := range t.eventsToTrace {
		params := eventsParams[e]
		var paramsTypes uint64
		var paramsNames uint64
		for n, param := range params {
			paramsTypes = paramsTypes | (uint64(param.encType) << (8 * n))
			paramsNames = paramsNames | (uint64(param.encName) << (8 * n))
		}
		leaf := make([]byte, 8)
		binary.LittleEndian.PutUint32(key, uint32(e))
		binary.LittleEndian.PutUint64(leaf, paramsTypes)
		paramsTypesBPFTable.Set(key, leaf)
		binary.LittleEndian.PutUint32(key, uint32(e))
		binary.LittleEndian.PutUint64(leaf, paramsNames)
		paramsNamesBPFTable.Set(key, leaf)

		event, ok := EventsIDToEvent[e]
		if !ok {
			continue
		}
		for _, probe := range event.Probes {
			if probe.attach == rawTracepoint && !supportRawTracepoints {
				// We fallback to regular tracepoint in case kernel doesn't support raw tracepoints (< 4.17)
				probe.attach = tracepoint
			}
			if probe.attach == sysCall {
				if e == ExecveEventID || e == ExecveatEventID {
					var tp int
					// execve functions require tail call on syscall enter as they perform extra work
					if supportRawTracepoints {
						tp, err = t.bpfModule.LoadRawTracepoint(fmt.Sprintf("syscall__%s", probe.fn))
					} else {
						tp, err = t.bpfModule.LoadTracepoint(fmt.Sprintf("syscall__%s", probe.fn))
					}
					if err != nil {
						return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
					}
					binary.LittleEndian.PutUint32(key, uint32(e))
					binary.LittleEndian.PutUint32(leaf, uint32(tp))
					sysEnterTailsBPFTable.Set(key, leaf)
				}
				continue
			}
			if probe.attach == kprobe {
				kp, err := t.bpfModule.LoadKprobe(probe.fn)
				if err != nil {
					return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
				}
				err = t.bpfModule.AttachKprobe(probe.event, kp, -1)
				if err != nil {
					return fmt.Errorf("error attaching kprobe %s: %v", probe.event, err)
				}
				continue
			}
			if probe.attach == kretprobe {
				kp, err := t.bpfModule.LoadKprobe(probe.fn)
				if err != nil {
					return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
				}
				err = t.bpfModule.AttachKretprobe(probe.event, kp, -1)
				if err != nil {
					return fmt.Errorf("error attaching kretprobe %s: %v", probe.event, err)
				}
				continue
			}
			if probe.attach == tracepoint {
				tp, err := t.bpfModule.LoadTracepoint(probe.fn)
				if err != nil {
					return fmt.Errorf("error loading tracepoint %s: %v", probe.fn, err)
				}
				err = t.bpfModule.AttachTracepoint(probe.event, tp)
				if err != nil {
					return fmt.Errorf("error attaching tracepoint %s: %v", probe.event, err)
				}
				continue
			}
			if probe.attach == rawTracepoint {
				tp, err := t.bpfModule.LoadRawTracepoint(probe.fn)
				if err != nil {
					return fmt.Errorf("error loading raw tracepoint %s: %v", probe.fn, err)
				}
				tpEvent := strings.Split(probe.event, ":")[1]
				err = t.bpfModule.AttachRawTracepoint(tpEvent, tp)
				if err != nil {
					return fmt.Errorf("error attaching raw tracepoint %s: %v", tpEvent, err)
				}
				continue
			}
		}
	}

	bpfConfig := bpf.NewTable(t.bpfModule.TableId("config_map"), t.bpfModule)

	binary.LittleEndian.PutUint32(key, uint32(configMode))
	binary.LittleEndian.PutUint32(leaf, t.config.Mode)
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configDetectOrigSyscall))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.DetectOriginalSyscall))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configExecEnv))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.ShowExecEnv))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configCaptureFiles))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.CaptureWrite))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configExtractDynCode))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.CaptureMem))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configTraceePid))
	binary.LittleEndian.PutUint32(leaf, uint32(os.Getpid()))
	bpfConfig.Set(key, leaf)

	pidsMap := bpf.NewTable(t.bpfModule.TableId("pids_map"), t.bpfModule)
	for _, pid := range t.config.PidsToTrace {
		binary.LittleEndian.PutUint32(key, uint32(pid))
		binary.LittleEndian.PutUint32(leaf, uint32(pid))
		pidsMap.Set(key, leaf)
	}

	// Load send_bin function to prog_array to be used as tail call
	progArrayBPFTable := bpf.NewTable(t.bpfModule.TableId("prog_array"), t.bpfModule)
	binary.LittleEndian.PutUint32(key, tailVfsWrite)
	kp, err := t.bpfModule.LoadKprobe("trace_ret_vfs_write_tail")
	if err != nil {
		return fmt.Errorf("error loading function trace_ret_vfs_write_tail: %v", err)
	}
	binary.LittleEndian.PutUint32(leaf, uint32(kp))
	progArrayBPFTable.Set(key, leaf)

	binary.LittleEndian.PutUint32(key, tailVfsWritev)
	kp, err = t.bpfModule.LoadKprobe("trace_ret_vfs_writev_tail")
	if err != nil {
		return fmt.Errorf("error loading function trace_ret_vfs_writev_tail: %v", err)
	}
	binary.LittleEndian.PutUint32(leaf, uint32(kp))
	progArrayBPFTable.Set(key, leaf)

	binary.LittleEndian.PutUint32(key, tailSendBin)
	kp, err = t.bpfModule.LoadKprobe("send_bin")
	if err != nil {
		return fmt.Errorf("error loading function send_bin: %v", err)
	}
	binary.LittleEndian.PutUint32(leaf, uint32(kp))
	progArrayBPFTable.Set(key, leaf)

	// Set filters given by the user to filter file write events
	fileFilterTable := bpf.NewTable(t.bpfModule.TableId("file_filter"), t.bpfModule)
	for i := 0; i < len(t.config.FilterFileWrite); i++ {
		binary.LittleEndian.PutUint32(key, uint32(i))
		leaf = []byte(t.config.FilterFileWrite[i])
		fileFilterTable.Set(key, leaf)
	}

	eventsBPFTable := bpf.NewTable(t.bpfModule.TableId("events"), t.bpfModule)
	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	t.eventsPerfMap, err = bpf.InitPerfMapWithPageCnt(eventsBPFTable, t.eventsChannel, t.lostEvChannel, t.config.PerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	fileWritesBPFTable := bpf.NewTable(t.bpfModule.TableId("file_writes"), t.bpfModule)
	t.fileWrChannel = make(chan []byte, 1000)
	t.lostWrChannel = make(chan uint64)
	t.fileWrPerfMap, err = bpf.InitPerfMapWithPageCnt(fileWritesBPFTable, t.fileWrChannel, t.lostWrChannel, t.config.BlobPerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing file_writes perf map: %v", err)
	}

	return nil
}

// Run starts the trace. it will run until interrupted
func (t *Tracee) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	t.printer.Preamble()
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	go t.processLostEvents()
	go t.runEventPipeline(done)
	go t.processFileWrites()
	<-sig
	t.eventsPerfMap.Stop() //TODO: should this be in Tracee.Close()?
	t.fileWrPerfMap.Stop() //TODO: should this be in Tracee.Close()?
	t.printer.Epilogue(t.stats)
	// Signal pipeline that Tracee exits by closing the done channel
	close(done)
	t.Close()
	return nil
}

// Close cleans up created resources
func (t *Tracee) Close() {
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

func copyFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}

func (t *Tracee) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.printer.Error(err)
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *Tracee) shouldProcessEvent(e RawEvent) bool {
	return true
}

func (t *Tracee) processEvent(ctx *context, args map[argTag]interface{}) error {
	switch ctx.EventID {
	case SecurityBprmCheckEventID:

		//cache this pid by it's mnt ns
		if ctx.Pid == 1 {
			t.pidsInMntns.ForceAddBucketItem(ctx.MntID, ctx.HostPid)
		} else {
			t.pidsInMntns.AddBucketItem(ctx.MntID, ctx.HostPid)
		}

		//capture executed files
		if t.config.CaptureExec {
			filePath, ok := args[t.EncParamName[ctx.EventID%2]["pathname"]].(string)
			if !ok {
				return fmt.Errorf("error parsing security_bprm_check args")
			}
			// path should be absolute, except for e.g memfd_create files
			if filePath[0] != '/' {
				return nil
			}

			destinationDirPath := filepath.Join(t.config.OutputPath, strconv.Itoa(int(ctx.MntID)))
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
				err = copyFileByPath(sourceFilePath, destinationFilePath)
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

// shouldPrintEvent decides whether or not the given event id should be printed to the output
func (t *Tracee) shouldPrintEvent(e RawEvent) bool {
	// Only print events requested by the user
	if !t.eventsToTrace[e.Ctx.EventID] {
		return false
	}
	return true
}

func (t *Tracee) prepareArgsForPrint(ctx *context, args map[argTag]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}
	switch ctx.EventID {
	case SysEnterEventID, SysExitEventID, CapCapableEventID:
		//show syscall name instead of id
		if id, isInt32 := args[t.EncParamName[ctx.EventID%2]["syscall"]].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args[t.EncParamName[ctx.EventID%2]["syscall"]] = event.Probes[0].event
				}
			}
		}
		if ctx.EventID == CapCapableEventID {
			if cap, isInt32 := args[t.EncParamName[ctx.EventID%2]["cap"]].(int32); isInt32 {
				args[t.EncParamName[ctx.EventID%2]["cap"]] = PrintCapability(cap)
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args[t.EncParamName[ctx.EventID%2]["prot"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["prot"]] = PrintMemProt(uint32(prot))
		}
	case PtraceEventID:
		if req, isInt32 := args[t.EncParamName[ctx.EventID%2]["request"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["request"]] = PrintPtraceRequest(req)
		}
	case PrctlEventID:
		if opt, isInt32 := args[t.EncParamName[ctx.EventID%2]["option"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["option"]] = PrintPrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args[t.EncParamName[ctx.EventID%2]["domain"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["domain"]] = PrintSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[t.EncParamName[ctx.EventID%2]["type"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["type"]] = PrintSocketType(uint32(typ))
		}
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.EventID%2]["addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.EventID%2]["addr"]] = s
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args[t.EncParamName[ctx.EventID%2]["mode"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["mode"]] = PrintAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.EventID%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = PrintExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID, SecurityFileOpenEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.EventID%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = PrintOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args[t.EncParamName[ctx.EventID%2]["mode"]].(uint32); isUint32 {
			args[t.EncParamName[ctx.EventID%2]["mode"]] = PrintInodeMode(mode)
		}
	case MemProtAlertEventID:
		if alert, isAlert := args[t.EncParamName[ctx.EventID%2]["alert"]].(alert); isAlert {
			args[t.EncParamName[ctx.EventID%2]["alert"]] = PrintAlert(alert)
		}
	case CloneEventID:
		if flags, isUint64 := args[t.EncParamName[ctx.EventID%2]["flags"]].(uint64); isUint64 {
			args[t.EncParamName[ctx.EventID%2]["flags"]] = PrintCloneFlags(flags)
		}
	case SendtoEventID, RecvfromEventID:
		addrTag := t.EncParamName[ctx.EventID%2]["dest_addr"]
		if ctx.EventID == RecvfromEventID {
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
	}

	return nil
}

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type context struct {
	Ts       uint64
	Pid      uint32
	Tid      uint32
	Ppid     uint32
	HostPid  uint32
	HostTid  uint32
	HostPpid uint32
	Uid      uint32
	MntID    uint32
	PidID    uint32
	Comm     [16]byte
	UtsName  [16]byte
	EventID  int32
	Retval   int64
	Argnum   uint8
	_        [7]byte //padding
}

func (t *Tracee) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.lostEvCounter.Increment(int(lost))
	}
}

func (t *Tracee) processFileWrites() {
	type chunkMeta struct {
		BinType  binType
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

			pathname := path.Join(t.config.OutputPath, strconv.Itoa(int(meta.MntID)))
			if err := os.MkdirAll(pathname, 0755); err != nil {
				t.handleError(err)
				continue
			}
			filename := ""
			metaBuff := bytes.NewBuffer(meta.Metadata[:])
			if meta.BinType == sendVfsWrite {
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
			} else if meta.BinType == sendMprotect {
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
				if _, err := f.Seek(0, os.SEEK_END); err != nil {
					f.Close()
					t.handleError(err)
					continue
				}
			} else {
				if _, err := f.Seek(int64(meta.Off), os.SEEK_SET); err != nil {
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
			t.stats.lostWrCounter.Increment(int(lost))
		}
	}
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	var size int32
	err = binary.Read(buff, binary.LittleEndian, &size)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	if size > 4096 {
		return "", fmt.Errorf("string size too big: %d", size)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) //last byte is string terminating null
	defer func() {
		var dummy int8
		binary.Read(buff, binary.LittleEndian, &dummy) //discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
// max length can be passed as `max` to optimize memory allocation, otherwise pass 0
func readStringVarFromBuff(buff io.Reader, max int) (string, error) {
	var err error
	var char int8
	res := make([]byte, max)
	err = binary.Read(buff, binary.LittleEndian, &char)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %v", err)
	}
	for count := 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		err = binary.Read(buff, binary.LittleEndian, &char)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %v", err)
		}
	}
	res = bytes.TrimLeft(res[:], "\000")
	return string(res), nil
}

func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
	var family int16
	err := binary.Read(buff, binary.LittleEndian, &family)
	if err != nil {
		return nil, err
	}
	res["sa_family"] = PrintSocketDomain(uint32(family))
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		var sunPathBuf [108]byte
		err := binary.Read(buff, binary.LittleEndian, &sunPathBuf)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		trimmedPath := bytes.TrimLeft(sunPathBuf[:], "\000")
		sunPath := ""
		if len(trimmedPath) != 0 {
			sunPath, err = readStringVarFromBuff(bytes.NewBuffer(trimmedPath), 108)
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		res["sun_path"] = sunPath
	case 2: // AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		var port uint16
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))
		var addr uint32
		err = binary.Read(buff, binary.BigEndian, &addr)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = PrintUint32IP(addr)
	case 10: // AF_INET6
		/*
			struct sockaddr_in6 {
				sa_family_t     sin6_family;   // AF_INET6
				in_port_t       sin6_port;     // port number
				uint32_t        sin6_flowinfo; // IPv6 flow information
				struct in6_addr sin6_addr;     // IPv6 address
				uint32_t        sin6_scope_id; // Scope ID (new in 2.4)
			};

			struct in6_addr {
				unsigned char   s6_addr[16];   // IPv6 address
			};
		*/
		var port uint16
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_port"] = strconv.Itoa(int(port))

		var flowinfo uint32
		err = binary.Read(buff, binary.BigEndian, &flowinfo)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_flowinfo"] = strconv.Itoa(int(flowinfo))
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_addr"] = Print16BytesSliceIP(addr)
		var scopeid uint32
		err = binary.Read(buff, binary.BigEndian, &scopeid)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_scopeid"] = strconv.Itoa(int(scopeid))
	}
	return res, nil
}

// alert struct encodes a security alert message with a timestamp
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `alert_t` struct in the ebpf code.
type alert struct {
	Ts      uint64
	Msg     uint32
	Payload uint8
}

func readArgFromBuff(dataBuff io.Reader) (argTag, interface{}, error) {
	var err error
	var res interface{}
	var argTag argTag
	var argType argType
	err = binary.Read(dataBuff, binary.LittleEndian, &argType)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg type: %v", err)
	}
	err = binary.Read(dataBuff, binary.LittleEndian, &argTag)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg tag: %v", err)
	}
	switch argType {
	case intT:
		var data int32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case uintT, devT, modeT:
		var data uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case longT:
		var data int64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case ulongT, offT, sizeT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case pointerT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = uintptr(data)
	case sockAddrT:
		res, err = readSockaddrFromBuff(dataBuff)
	case alertT:
		var data alert
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case strT:
		res, err = readStringFromBuff(dataBuff)
	case strArrT:
		var ss []string
		var arrLen uint8
		err = binary.Read(dataBuff, binary.LittleEndian, &arrLen)
		if err != nil {
			return argTag, nil, fmt.Errorf("error reading string array number of elements: %v", err)
		}
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return argTag, nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)
		}
		res = ss
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return argTag, nil, fmt.Errorf("error unknown arg type %v", argType)
	}
	if err != nil {
		return argTag, nil, err
	}
	return argTag, res, nil
}
