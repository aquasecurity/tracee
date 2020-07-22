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
	if tc.OutputFormat != "table" && tc.OutputFormat != "json" && tc.OutputFormat != "gob" {
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

	if cfg.CaptureExec {
		essentialEvents[EventsNameToID["security_bprm_check"]] = false
	}
	if cfg.CaptureWrite {
		essentialEvents[EventsNameToID["vfs_write"]] = false
	}
	if cfg.SecurityAlerts || cfg.CaptureMem {
		essentialEvents[EventsNameToID["mmap"]] = false
		essentialEvents[EventsNameToID["mprotect"]] = false
	}
	if cfg.CaptureMem {
		essentialEvents[EventsNameToID["mem_prot_alert"]] = false
	}
	// create tracee
	t := &Tracee{
		config: cfg,
	}
	t.printer = newEventPrinter(t.config.OutputFormat, t.config.EventsFile, t.config.ErrorsFile)

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

	// compile final list of events to trace including essential events while at the same time record which essentials were requested by the user
	// to build this list efficiently we use the `tmpset` variable as follows:
	// 1. the presence of an entry says we have already seen this event (key)
	// 2. the value says if this event is essential
	eventsToTraceFinal := make([]int32, 0, len(t.config.EventsToTrace))
	tmpset := make(map[int32]bool, len(t.config.EventsToTrace))
	for e := range essentialEvents {
		eventsToTraceFinal = append(eventsToTraceFinal, e)
		tmpset[e] = true
	}
	for _, e := range t.config.EventsToTrace {
		// Set chosen events map according to events chosen by the user
		binary.LittleEndian.PutUint32(key, uint32(e))
		binary.LittleEndian.PutUint32(leaf, boolToUInt32(true))
		chosenEvents.Set(key, leaf)

		essential, exists := tmpset[e]
		// exists && essential = user requested essential
		// exists && !essential = dup event
		// !exists && essential = should never happen
		// !exists && !essential = user requested event
		if exists {
			if essential {
				essentialEvents[e] = true
			}
		} else {
			eventsToTraceFinal = append(eventsToTraceFinal, e)
			tmpset[e] = false
		}
	}

	sysPrefix := bpf.GetSyscallPrefix()
	for _, e := range eventsToTraceFinal {
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

	binary.LittleEndian.PutUint32(key, uint32(configContMode))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.ContainerMode))
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

	// Load send_bin function to prog_array to be used as tail call
	progArrayBPFTable := bpf.NewTable(t.bpfModule.TableId("prog_array"), t.bpfModule)
	binary.LittleEndian.PutUint32(key, tailVfsWrite)
	kp, err := t.bpfModule.LoadKprobe("do_trace_ret_vfs_write")
	if err != nil {
		return fmt.Errorf("error loading function do_trace_ret_vfs_write: %v", err)
	}
	binary.LittleEndian.PutUint32(leaf, uint32(kp))
	progArrayBPFTable.Set(key, leaf)

	binary.LittleEndian.PutUint32(key, tailVfsRead)
	kp, err = t.bpfModule.LoadKprobe("do_trace_ret_vfs_read")
	if err != nil {
		return fmt.Errorf("error loading function do_trace_ret_vfs_read: %v", err)
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
	t.printer.Preamble()
	t.eventsPerfMap.Start()
	t.fileWrPerfMap.Start()
	go t.processEvents()
	go t.processFileWrites()
	<-sig
	t.eventsPerfMap.Stop() //TODO: should this be in Tracee.Close()?
	t.fileWrPerfMap.Stop() //TODO: should this be in Tracee.Close()?
	t.printer.Epilogue(t.stats)
	t.Close()
	return nil
}

// Close cleans up created resources
func (t Tracee) Close() {
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

// shouldPrintEvent decides whether or not the given event id should be printed to the output
func (t Tracee) shouldPrintEvent(e int32) bool {
	// if we got a trace for a non-essential event, it means the user explicitly requested it (using `-e`), or the user doesn't care (trace all by default). In both cases it's ok to print.
	// for essential events we need to check if the user actually wanted this event
	if print, isEssential := essentialEvents[e]; isEssential {
		return print
	}
	return true
}

func (t *Tracee) processEvent(ctx *context, args []interface{}) error {
	eventName := EventsIDToEvent[ctx.Event_id].Name

	//show event name for raw_syscalls
	if eventName == "raw_syscalls" {
		if id, isInt32 := args[0].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				args[0] = event.Probes[0].event
			}
		}
	}

	//capture executed files
	if t.config.CaptureExec && (eventName == "security_bprm_check") {
		var err error

		sourceFilePath, ok := args[0].(string)
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

		destinationDirPath := filepath.Join(t.config.OutputPath, strconv.Itoa(int(ctx.Mnt_id)))
		if err := os.MkdirAll(destinationDirPath, 0755); err != nil {
			return err
		}
		destinationFilePath := filepath.Join(destinationDirPath, fmt.Sprintf("exec.%d.%s", ctx.Ts, filepath.Base(sourceFilePath)))

		err = copyFileByPath(sourceFilePath, destinationFilePath)
		if err != nil {
			return err
		}
	}

	return nil
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

func (t Tracee) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.printer.Error(err)
}

func (t *Tracee) processEvents() {
	for {
		select {
		case dataRaw := <-t.eventsChannel:
			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				t.handleError(err)
				continue
			}
			args := make([]interface{}, ctx.Argnum)
			for i := 0; i < int(ctx.Argnum); i++ {
				args[i], err = readArgFromBuff(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}
			}
			err = t.processEvent(&ctx, args)
			if err != nil {
				t.handleError(err)
				continue
			}
			if t.shouldPrintEvent(ctx.Event_id) {
				t.stats.eventCounter.Increment()
				evt, err := newEvent(ctx, args)
				if err != nil {
					t.handleError(err)
					continue
				}
				t.printer.Print(evt)
			}
		case lost := <-t.lostEvChannel:
			t.stats.lostEvCounter.Increment(int(lost))
		}
	}
}

func (t *Tracee) processFileWrites() {
	type chunkMeta struct {
		BinType  uint8
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

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type context struct {
	Ts       uint64
	Pid      uint32
	Tid      uint32
	Ppid     uint32
	Uid      uint32
	Mnt_id   uint32
	Pid_id   uint32
	Comm     [16]byte
	Uts_name [16]byte
	Event_id int32
	Argnum   uint8
	_        [3]byte
	Retval   int64
}

func readContextFromBuff(buff io.Reader) (context, error) {
	var res context
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readArgTypeFromBuff(buff io.Reader) (argType, error) {
	var res argType
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	size, err := readInt32FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) //last byte is string terminating null
	defer func() {
		_, _ = readInt8FromBuff(buff) //discard last byte which is string terminating null
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
	res := make([]byte, max)
	char, err := readInt8FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %v", err)
	}
	for count := 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		char, err = readInt8FromBuff(buff)
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

func readInt8FromBuff(buff io.Reader) (int8, error) {
	var res int8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt8FromBuff(buff io.Reader) (uint8, error) {
	var res uint8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readInt16FromBuff(buff io.Reader) (int16, error) {
	var res int16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt16FromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt16BigendFromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

func readInt32FromBuff(buff io.Reader) (int32, error) {
	var res int32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt32FromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt32BigendFromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

func readInt64FromBuff(buff io.Reader) (int64, error) {
	var res int64
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt64FromBuff(buff io.Reader) (uint64, error) {
	var res uint64
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
	family, err := readInt16FromBuff(buff)
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
		sunPath, err := readStringVarFromBuff(bytes.NewBuffer(bytes.TrimLeft(sunPathBuf[:], "\000")), 108)
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
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))
		addr, err := readUInt32BigendFromBuff(buff)
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
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_port"] = strconv.Itoa(int(port))

		flowinfo, err := readUInt32BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_flowinfo"] = strconv.Itoa(int(flowinfo))
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_addr"] = Print16BytesSliceIP(addr)
		scopeid, err := readUInt32BigendFromBuff(buff)
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

func readAlertFromBuff(buff io.Reader) (alert, error) {
	var res alert
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readArgFromBuff(dataBuff io.Reader) (interface{}, error) {
	var err error
	var res interface{}
	at, err := readArgTypeFromBuff(dataBuff)
	if err != nil {
		return res, fmt.Errorf("error reading arg type: %v", err)
	}
	switch at {
	case intT:
		res, err = readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case uintT, devT:
		res, err = readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case longT:
		res, err = readInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case ulongT, offT, sizeT:
		res, err = readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strT:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strArrT:
		var ss []string
		// assuming there's at least one element in the array
		et, err := readArgTypeFromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading string array element type: %v", err)
		}
		for et != strArrT {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)

			et, err = readArgTypeFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string array element type: %v", err)
			}
		}
		res = ss
	case capT:
		cap, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading capability arg: %v", err)
		}
		res = PrintCapability(cap)
	case syscallT:
		sc, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading syscall arg: %v", err)
		}
		res = strconv.Itoa(int(sc))
		if event, ok := EventsIDToEvent[sc]; ok {
			if event.Probes[0].attach == sysCall {
				res = event.Probes[0].event
			}
		}
	case modeT:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintInodeMode(mode)
	case protFlagsT:
		prot, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintMemProt(prot)
	case pointerT:
		ptr, err := readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = fmt.Sprintf("0x%X", ptr)
	case sockAddrT:
		sockaddr, err := readSockaddrFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		var s string
		for key, val := range sockaddr {
			s += fmt.Sprintf("'%s': '%s',", key, val)
		}
		s = strings.TrimSuffix(s, ",")
		s = fmt.Sprintf("{%s}", s)
		res = s
	case openFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintOpenFlags(flags)
	case accessModeT:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintAccessMode(mode)
	case execFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintExecFlags(flags)
	case sockDomT:
		dom, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketDomain(dom)
	case sockTypeT:
		t, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketType(t)
	case prctlOptT:
		op, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPrctlOption(op)
	case ptraceReqT:
		req, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPtraceRequest(req)
	case alertT:
		alert, err := readAlertFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintAlert(alert)
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return nil, fmt.Errorf("error unknown arg type %v", at)
	}
	return res, nil
}
