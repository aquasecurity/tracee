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

	bpf "github.com/iovisor/gobpf/bcc"
)

// taskComm is a `TASK_COMM_LEN` long string.
// `TASK_COMM_LEN` is defined in the linux header linux/sched.h
type taskComm [16]byte

// String implemets the Stringer interface
func (tc taskComm) String() string {
	len := 0
	for i, b := range tc {
		if b == 0 {
			len = i
			break
		}
	}
	return string(tc[:len])
}

// MarshalText implements the TextMarshaler interface, which is used by JSONMarshaler and others
func (tc taskComm) MarshalText() ([]byte, error) {
	return []byte(tc.String()), nil
}

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type context struct {
	Ts      uint64   `json:"time"`
	Pid     uint32   `json:"pid"`
	Tid     uint32   `json:"tid"`
	Ppid    uint32   `json:"ppid"`
	Uid     uint32   `json:"uid"`
	MntId   uint32   `json:"mnt_ns"`
	PidId   uint32   `json:"pid_ns"`
	Comm    taskComm `json:"process_name"`
	UtsName taskComm `json:"uts_name"`
	Eventid int32    `json:"api"`
	Argnum  uint8    `json:"arguments_count"`
	_       [3]byte  // padding for Argnum
	Retval  int64    `json:"return_value"`
}

// TraceeConfig is a struct containing user defined configuration of tracee
type TraceeConfig struct {
	EventsToTrace         []int32
	ContainerMode         bool
	DetectOriginalSyscall bool
	ShowExecEnv           bool
	OutputFormat          string
	PerfBufferSize        int
	OutputPath            string
	CaptureFiles          bool
	FilterFileWrite       []string
	EventsFile            *os.File
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
		if _, ok := EventsIDToName[e]; !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
	}
	if (tc.PerfBufferSize & (tc.PerfBufferSize - 1)) != 0 {
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
	eventCounter  int
	errorCounter  int
	lostEvCounter int
	lostWrCounter int
}

// New creates a new Tracee instance based on a given valid TraceeConfig
func New(cfg TraceeConfig) (*Tracee, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	// create tracee
	t := &Tracee{
		config: cfg,
	}
	switch t.config.OutputFormat {
	case "table":
		t.printer = &tableEventPrinter{
			out:    cfg.EventsFile,
			tracee: t,
		}
	case "json":
		t.printer = &jsonEventPrinter{
			out: cfg.EventsFile,
		}
	case "gob":
		t.printer = &gobEventPrinter{
			out: cfg.EventsFile,
		}
	}
	t.printer.Init()

	p, err := getEBPFProgram()
	if err != nil {
		return nil, err
	}
	err = t.initBPF(p)
	if err != nil {
		t.Close()
		return nil, err
	}

	return t, nil
}

func (t *Tracee) initBPF(ebpfProgram string) error {
	var err error

	t.bpfModule = bpf.NewModule(ebpfProgram, []string{})

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
		if eName, isSyscall := EventsSyscalls[e]; isSyscall {
			kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", eName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", eName, err)
			}
			err = t.bpfModule.AttachKprobe(sysPrefix+eName, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", eName, err)
			}
			kp, err = t.bpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", eName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", eName, err)
			}
			err = t.bpfModule.AttachKretprobe(sysPrefix+eName, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kretprobe %s: %v", eName, err)
			}
		} else if eName, isKprobe := EventsKprobes[e]; isKprobe {
			kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("trace_%s", eName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", eName, err)
			}
			err = t.bpfModule.AttachKprobe(eName, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", eName, err)
			}
			if eName, isKretprobe := EventsKretprobes[e]; isKretprobe {
				kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", eName))
				if err != nil {
					return fmt.Errorf("error loading kprobe %s: %v", eName, err)
				}
				err = t.bpfModule.AttachKretprobe(eName, kp, -1)
				if err != nil {
					return fmt.Errorf("error attaching kretprobe %s: %v", eName, err)
				}
			}
		} else if eName, isTracepoint := EventsTracepoints[e]; isTracepoint {
			tp, err := t.bpfModule.LoadTracepoint(fmt.Sprintf("tracepoint__%s__sys_enter", eName))
			if err != nil {
				return fmt.Errorf("error loading tracepoint %s: %v", eName, err)
			}
			err = t.bpfModule.AttachTracepoint(fmt.Sprintf("%s:sys_enter", eName), tp)
			if err != nil {
				return fmt.Errorf("error attaching tracepoint %s: %v", eName, err)
			}
		}

	}

	bpfConfig := bpf.NewTable(t.bpfModule.TableId("config_map"), t.bpfModule)
	key := make([]byte, 4)
	leaf := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, uint32(CONFIG_CONT_MODE))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.ContainerMode))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(CONFIG_DETECT_ORIG_SYSCALL))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.DetectOriginalSyscall))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(CONFIG_EXEC_ENV))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.ShowExecEnv))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(CONFIG_CAPTURE_FILES))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.CaptureFiles))
	bpfConfig.Set(key, leaf)

	// Load send_bin function to prog_array to be used as tail call
	progArrayBPFTable := bpf.NewTable(t.bpfModule.TableId("prog_array"), t.bpfModule)
	binary.LittleEndian.PutUint32(key, uint32(0))
	kp, err := t.bpfModule.LoadKprobe("do_trace_ret_vfs_write")
	if err != nil {
		return fmt.Errorf("error loading function do_trace_ret_vfs_write: %v", err)
	}
	binary.LittleEndian.PutUint32(leaf, uint32(kp))
	progArrayBPFTable.Set(key, leaf)

	binary.LittleEndian.PutUint32(key, uint32(1))
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
	t.fileWrPerfMap, err = bpf.InitPerfMapWithPageCnt(fileWritesBPFTable, t.fileWrChannel, t.lostWrChannel, t.config.PerfBufferSize)
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
	t.printer.Epilogue()
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

func (t *Tracee) processEvents() {
	for {
		select {
		case dataRaw := <-t.eventsChannel:
			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				t.errorCounter = t.errorCounter + 1
				continue
			}
			args := make([]interface{}, ctx.Argnum)
			for i := 0; i < int(ctx.Argnum); i++ {
				args[i], err = readArgFromBuff(dataBuff)
				if err != nil {
					t.errorCounter = t.errorCounter + 1
					continue
				}
			}
			if t.shouldPrintEvent(ctx.Eventid) {
				t.eventCounter = t.eventCounter + 1
				t.printer.Print(ctx, args)
			}
		case lost := <-t.lostEvChannel:
			t.lostEvCounter = t.lostEvCounter + int(lost)
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
	}

	for {
		select {
		case dataRaw := <-t.fileWrChannel:
			dataBuff := bytes.NewBuffer(dataRaw)
			var meta chunkMeta
			err := binary.Read(dataBuff, binary.LittleEndian, &meta)
			if err != nil {
				t.errorCounter = t.errorCounter + 1
				continue
			}

			if meta.Size <= 0 {
				t.errorCounter = t.errorCounter + 1
				continue
			}
			if dataBuff.Len() <= int(meta.Size) {
				t.errorCounter = t.errorCounter + 1
				continue
			}

			pathname := path.Join(t.config.OutputPath, strconv.Itoa(int(meta.MntID)))
			if err := os.MkdirAll(pathname, 0755); err != nil {
				t.errorCounter = t.errorCounter + 1
				continue
			}
			filename := ""
			if meta.BinType == 1 {
				metaBuff := bytes.NewBuffer(meta.Metadata[:])
				var vfsMeta vfsWriteMeta
				err = binary.Read(metaBuff, binary.LittleEndian, &vfsMeta)
				if err != nil {
					t.errorCounter = t.errorCounter + 1
					continue
				}
				filename = fmt.Sprintf("write.dev-%d.inode-%d", vfsMeta.DevID, vfsMeta.Inode)
			} else {
				t.errorCounter = t.errorCounter + 1
				continue
			}

			fullname := path.Join(pathname, filename)

			f, err := os.OpenFile(fullname, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				t.errorCounter = t.errorCounter + 1
				continue
			}
			if _, err := f.Seek(int64(meta.Off), os.SEEK_SET); err != nil {
				f.Close()
				t.errorCounter = t.errorCounter + 1
				continue
			}

			dataBytes, err := readByteSliceFromBuff(dataBuff, int(meta.Size))
			if err != nil {
				f.Close()
				t.errorCounter = t.errorCounter + 1
				continue
			}
			if _, err := f.Write(dataBytes); err != nil {
				f.Close()
				t.errorCounter = t.errorCounter + 1
				continue
			}
			if err := f.Close(); err != nil {
				t.errorCounter = t.errorCounter + 1
				continue
			}
		case lost := <-t.lostWrChannel:
			t.lostWrCounter = t.lostWrCounter + int(lost)
		}
	}
}

func readContextFromBuff(buff io.Reader) (context, error) {
	var res context
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readArgTypeFromBuff(buff io.Reader) (ArgType, error) {
	var res ArgType
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
	for char != 0 {
		res = append(res, byte(char))
		char, err = readInt8FromBuff(buff)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %v", err)
		}
	}
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
		sunPath, err := readStringVarFromBuff(buff, 108)
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

func readArgFromBuff(dataBuff io.Reader) (interface{}, error) {
	var err error
	var res interface{}
	at, err := readArgTypeFromBuff(dataBuff)
	if err != nil {
		return res, fmt.Errorf("error reading arg type: %v", err)
	}
	switch at {
	case INT_T:
		res, err = readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case UINT_T, DEV_T_T:
		res, err = readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case LONG_T:
		res, err = readInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case ULONG_T, OFF_T_T, SIZE_T_T:
		res, err = readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case STR_T:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case STR_ARR_T:
		var ss []string
		// assuming there's at least one element in the array
		et, err := readArgTypeFromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading string array element type: %v", err)
		}
		for et != STR_ARR_T {
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
	case CAP_T:
		cap, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading capability arg: %v", err)
		}
		res = PrintCapability(cap)
	case SYSCALL_T:
		sc, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading syscall arg: %v", err)
		}
		res = PrintSyscall(sc)
	case MODE_T_T:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintInodeMode(mode)
	case PROT_FLAGS_T:
		prot, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintMemProt(prot)
	case POINTER_T:
		ptr, err := readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = fmt.Sprintf("0x%X", ptr)
	case SOCKADDR_T:
		sockaddr, err := readSockaddrFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = fmt.Sprintf("%v", sockaddr)[3:] // remove the leading "map" string
	case OPEN_FLAGS_T:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintOpenFlags(flags)
	case ACCESS_MODE_T:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintAccessMode(mode)
	case EXEC_FLAGS_T:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintExecFlags(flags)
	case SOCK_DOM_T:
		dom, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketDomain(dom)
	case SOCK_TYPE_T:
		t, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketType(t)
	case PRCTL_OPT_T:
		op, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPrctlOption(op)
	case PTRACE_REQ_T:
		req, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPrctlOption(req)
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return nil, fmt.Errorf("error unknown arg type %v", at)
	}
	return res, nil
}
