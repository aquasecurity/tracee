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
	ContainerMode         bool
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
	t.printer = newEventPrinter(t.config.OutputFormat, t.config.EventsFile, t.config.ErrorsFile)
	t.eventsToTrace = make(map[int32]bool, len(t.config.EventsToTrace))
	for _, e := range t.config.EventsToTrace {
		// Map value is true iff events requested by the user
		t.eventsToTrace[e] = true
	}

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
	return t, nil
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

	// compile final list of events to trace including essential events
	// if an essential event was not requested by the user, set its map value to false
	for id, event := range EventsIDToEvent {
		if event.EssentialEvent && !t.eventsToTrace[id] {
			// Essential event was not requested by the user - add it to map
			// Map value is false iff an essential event was not requested by the user
			t.eventsToTrace[id] = false
		}
	}

	sysPrefix := bpf.GetSyscallPrefix()
	for e, _ := range t.eventsToTrace {
		event, ok := EventsIDToEvent[e]
		if !ok {
			continue
		}
		for _, probe := range event.Probes {
			if probe.attach == sysCall {
				kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", probe.fn))
				if err != nil {
					return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
				}
				err = t.bpfModule.AttachKprobe(sysPrefix+probe.event, kp, -1)
				if err != nil {
					return fmt.Errorf("error attaching kprobe %s: %v", probe.event, err)
				}
				kp, err = t.bpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", probe.fn))
				if err != nil {
					return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
				}
				err = t.bpfModule.AttachKretprobe(sysPrefix+probe.event, kp, -1)
				if err != nil {
					return fmt.Errorf("error attaching kretprobe %s: %v", probe.event, err)
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
		}
	}

	bpfConfig := bpf.NewTable(t.bpfModule.TableId("config_map"), t.bpfModule)

	mode := modeSystem
	if t.config.ContainerMode {
		mode = modeContainer
	} else if len(t.config.PidsToTrace) > 0 {
		mode = modePid
	}

	binary.LittleEndian.PutUint32(key, uint32(configMode))
	binary.LittleEndian.PutUint32(leaf, mode)
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

	pidsMap := bpf.NewTable(t.bpfModule.TableId("pids_map"), t.bpfModule)
	for _, pid := range t.config.PidsToTrace {
		binary.LittleEndian.PutUint32(key, uint32(pid))
		binary.LittleEndian.PutUint32(leaf, uint32(pid))
		pidsMap.Set(key, leaf)
	}

	// Load send_bin function to prog_array to be used as tail call
	progArrayBPFTable := bpf.NewTable(t.bpfModule.TableId("prog_array"), t.bpfModule)
	binary.LittleEndian.PutUint32(key, tailVfsWrite)
	kp, err := t.bpfModule.LoadKprobe("do_trace_ret_vfs_write")
	if err != nil {
		return fmt.Errorf("error loading function do_trace_ret_vfs_write: %v", err)
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
		//capture executed files
		if t.config.CaptureExec {
			var err error
			sourceFilePath, ok := args[TagPathname].(string)
			if !ok {
				return fmt.Errorf("error parsing security_bprm_check args")
			}
			// path should be absolute, except for e.g memfd_create files
			if sourceFilePath[0] != '/' {
				return nil
			}
			sourceFileStat, err := os.Stat(sourceFilePath)
			if err != nil {
				return err
			}
			sourceCtime := sourceFileStat.Sys().(*syscall.Stat_t).Ctim.Nano()
			lastCtime, ok := t.capturedFiles[sourceFilePath]
			if ok && lastCtime == sourceCtime {
				return nil
			}
			t.capturedFiles[sourceFilePath] = sourceCtime

			destinationDirPath := filepath.Join(t.config.OutputPath, strconv.Itoa(int(ctx.MntID)))
			if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
				return err
			}
			destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", ctx.Ts, filepath.Base(sourceFilePath)))

			err = copyFileByPath(sourceFilePath, destinationFilePath)
			if err != nil {
				return err
			}
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
	switch e.Ctx.EventID {
	case RawSyscallsEventID:
		if id, isInt32 := e.RawArgs[TagSyscall].(int32); isInt32 {
			event, isKnown := EventsIDToEvent[id]
			if !isKnown {
				t.handleError(fmt.Errorf("raw_syscalls: unknown syscall id: %d", id))
				return false
			}
			if event.Probes[0].attach != sysCall {
				t.handleError(fmt.Errorf("raw_syscalls: unknown syscall id: %d", id))
				return false
			}
			if event.Name != "reserved" {
				// We already monitor this system call by another event
				return false
			}
		}
	}
	return true
}

func (t *Tracee) prepareArgsForPrint(ctx *context, args map[argTag]interface{}) error {
	switch ctx.EventID {
	case RawSyscallsEventID, CapCapableEventID:
		//show syscall name instead of id
		if id, isInt32 := args[TagSyscall].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args[TagSyscall] = event.Probes[0].event
				}
			}
		}
		if ctx.EventID == CapCapableEventID {
			if cap, isInt32 := args[TagCap].(int32); isInt32 {
				args[TagCap] = PrintCapability(cap)
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args[TagProt].(int32); isInt32 {
			args[TagProt] = PrintMemProt(uint32(prot))
		}
		if addr, isUint64 := args[TagAddr].(uint64); isUint64 {
			args[TagAddr] = fmt.Sprintf("0x%X", addr)
		}
	case PtraceEventID:
		if req, isInt32 := args[TagRequest].(int32); isInt32 {
			args[TagRequest] = PrintPtraceRequest(req)
		}
		if addr, isUint64 := args[TagAddr].(uint64); isUint64 {
			args[TagAddr] = fmt.Sprintf("0x%X", addr)
		}
		if addr, isUint64 := args[TagData].(uint64); isUint64 {
			args[TagData] = fmt.Sprintf("0x%X", addr)
		}
	case ProcessVmReadvEventID, ProcessVmWritevEventID:
		if addr, isUint64 := args[TagLocalIov].(uint64); isUint64 {
			args[TagLocalIov] = fmt.Sprintf("0x%X", addr)
		}
		if addr, isUint64 := args[TagRemoteIov].(uint64); isUint64 {
			args[TagRemoteIov] = fmt.Sprintf("0x%X", addr)
		}
	case InitModuleEventID:
		if addr, isUint64 := args[TagModuleImage].(uint64); isUint64 {
			args[TagModuleImage] = fmt.Sprintf("0x%X", addr)
		}
	case PrctlEventID:
		if opt, isInt32 := args[TagOption].(int32); isInt32 {
			args[TagOption] = PrintPrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args[TagDomain].(int32); isInt32 {
			args[TagDomain] = PrintSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[TagType].(int32); isInt32 {
			args[TagType] = PrintSocketType(uint32(typ))
		}
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args[TagAddr].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[TagAddr] = s
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args[TagMode].(int32); isInt32 {
			args[TagMode] = PrintAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args[TagFlags].(int32); isInt32 {
			args[TagFlags] = PrintExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID, SecurityFileOpenEventID:
		if flags, isInt32 := args[TagFlags].(int32); isInt32 {
			args[TagFlags] = PrintOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args[TagMode].(uint32); isUint32 {
			args[TagMode] = PrintInodeMode(mode)
		}
	case MemProtAlertEventID:
		if alert, isAlert := args[TagAlert].(alert); isAlert {
			args[TagAlert] = PrintAlert(alert)
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
	Argnum   uint8
	_        [3]byte //padding for Argnum (start address should be devisible by size of member)
	Retval   int64
	_        [4]byte //padding for the struct (size of struct should be devisible by size of largest member)
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
				filename = fmt.Sprintf("write.dev-%d.inode-%d", vfsMeta.DevID, vfsMeta.Inode)
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
	case ulongT, offT, sizeT, pointerT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
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
