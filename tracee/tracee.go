package tracee

import (
	"fmt"
	"io"
	"bytes"
	"io/ioutil"
	"os"
	"os/signal"
	"encoding/binary"
	//"encoding/hex"
	bpf "github.com/iovisor/gobpf/bcc"
)

// taskComm is a `TASK_COMM_LEN` long string.
// `TASK_COMM_LEN` is defined in the linux header linux/sched.h
type taskComm [16]byte

// String implemets the Stringer interface
func (tc taskComm) String() string {
	len := 0
	for i, b := range tc {
		if (b==0) {
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

// contex struct contains common metadata that is collected for all types of events
// original size is 77 bytes but with padding it's 80 bytes
// TODO: review naming conventions for the fields here
type context struct {
	Ts uint64 `json:"ts"`
  Pid uint32 `json:"pid"`
  Tid uint32 `json:"tid"`
  Ppid uint32 `json:"ppid"`
  Uid uint32 `json:"uid"`
  MntId uint32 `json:"mnt_id"`
  PidId uint32 `json:"ppid_id"`
  Comm taskComm `json:"comm"`
  UtsName taskComm `json:"uts_name"`
  Eventid uint32 `json:"eventid"`
  Argnum uint32 `json:"argnum"` //originally u8 but with padding it's uint32
	Retval int64 `json:"retval"`
}

// TraceConfig is a struct containing user defined configuration of tracee
// TODO: TraceConfig or TraceeConfig?
type TraceConfig struct {
	Syscalls map[string]bool
	Sysevents map[string]bool
	ContainerMode bool
	DetectOriginalSyscall bool
	OutputFormat string
}

// Validate does static validation of the configuration
// TODO: if error in golang is same as exception then this is abusing error
func (tc TraceConfig) Validate() error {
	if tc.Syscalls == nil || tc.Sysevents == nil {
		return fmt.Errorf("trace config validation failed: sysevents or syscalls is nil")
	}
	if tc.OutputFormat != "table" && tc.OutputFormat != "json" {
		return fmt.Errorf("trace config validation failed: unrecognized output format: %s", tc.OutputFormat)
	}
	for sc, wanted := range tc.Syscalls {
		_, valid := Syscalls[sc]
		if wanted && !valid {
			return fmt.Errorf("invalid syscall to trace: %s", sc)
		}
	}
	for se, wanted := range tc.Sysevents {
		_, valid := Sysevents[se]
		if wanted && !valid {
			return fmt.Errorf("invalid sysevent to trace: %s", se)
		}
	}
	return nil
}

// NewConfig creates a new TraceConfig instance based on the given configuration
func NewConfig(eventsToTrace []string, containerMode bool, detectOriginalSyscall bool, outputFormat string) (*TraceConfig, error) {
	//separate eventsToTrace into syscalls and sysevents
	syscalls := make(map[string]bool)
	sysevents := make(map[string]bool)
	for _, e := range eventsToTrace {
		if enabled, ok := Syscalls[e]; ok{
			syscalls[e] = enabled
		}
		if enabled, ok := Sysevents[e]; ok {
			sysevents[e] = enabled
		}
	}

	tc := TraceConfig{
		Syscalls: syscalls,
		Sysevents: sysevents,
		ContainerMode: containerMode,
		DetectOriginalSyscall: detectOriginalSyscall,
		OutputFormat:outputFormat,
	}

	err := tc.Validate()
	if err != nil {
		return nil, err
	}
	return &tc, nil
}

// Tracee traces system calls and events using eBPF
type Tracee struct {
	config TraceConfig
	bpfProgramPath string
	bpfModule *bpf.Module
	bpfPerfMap *bpf.PerfMap
	eventsChannel chan []byte
	printer eventPrinter
}

// New creates a new Tracee instance based on a given valid TraceConfig
func New(cfg TraceConfig) (*Tracee, error) {
	var err error

	// validation
	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}
	bpfFile := "./tracee/event_monitor_ebpf.c"
	_, err = os.Stat(bpfFile)
	if os.IsNotExist(err) {
			return nil, fmt.Errorf("error finding bpf C file at: %s", bpfFile)
	}

	// ensure essential syscalls and events are being traced
	for _, sc := range essentialSyscalls {
		cfg.Syscalls[sc] = true
	}
	for _, se := range essentialSysevents {
		cfg.Sysevents[se] = true
	}

	// create tracee
	t := &Tracee{
		config: cfg,
		bpfProgramPath: bpfFile,
	}
	switch t.config.OutputFormat {
	case "table":
		t.printer = tableEventPrinter{}
	case "json":
		t.printer = jsonEventPrinter{}
	}

	err = t.initBPF()
	if err != nil {
		t.Close()
		return nil, err
	}

	return t, nil
}

// Run starts the trace. it will run until interrupted
func (t Tracee) Run() error {	
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	t.printer.Preamble()
	t.bpfPerfMap.Start()
	go t.processEvents() 
	<-sig
	t.bpfPerfMap.Stop() //TODO: should this be in Tracee.Close()?
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

// TODO: Think where is the best place to call initBPF: from main.go / from tracee.New / from tracee.Run. currently from tracee.New
func (t *Tracee) initBPF() error {
	var err error

	bpfText, err := ioutil.ReadFile(t.bpfProgramPath)
	if err != nil {
		return fmt.Errorf("error reading ebpf program file: %v", err)
	}
	t.bpfModule = bpf.NewModule(string(bpfText), []string{})

	for sc := range t.config.Syscalls {
		kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", sc))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", sc, err)
		}
		err = t.bpfModule.AttachKprobe(bpf.GetSyscallFnName(sc), kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kprobe %s: %v", sc, err)
		}
		kp, err = t.bpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", sc))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", sc, err)
		}
		err = t.bpfModule.AttachKretprobe(bpf.GetSyscallFnName(sc), kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kretprobe %s: %v", sc, err)
		}
	}
	for se := range t.config.Sysevents {
		kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("trace_%s", se))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", se, err)
		}
		err = t.bpfModule.AttachKprobe(se, kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kprobe %s: %v", se, err)
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
	
	eventsBPFTable := bpf.NewTable(t.bpfModule.TableId("events"), t.bpfModule)
	t.eventsChannel = make(chan []byte, 1000)
	t.bpfPerfMap, err = bpf.InitPerfMap(eventsBPFTable, t.eventsChannel)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	return nil
}

func boolToUInt32(b bool) uint32{
	if b {
		return uint32(1)
	}
	return uint32(0)
}

func (t Tracee) processEvents() {
	for {
		dataRaw := <-t.eventsChannel
		dataBuff := bytes.NewBuffer(dataRaw)
		ctx, err := readContextFromBuff(dataBuff)
		if err != nil {
			// TODO: handle error
			continue
		}
		args := make([]interface{}, ctx.Argnum)
		for i:=0; i<int(ctx.Argnum); i++ {
			args[i], err = readArgFromBuff(dataBuff)
			if err != nil {
				// TODO: handle error
				continue
			}
		}
		t.printer.Print(ctx,args)
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
	res := make([]byte, size-1) //last byte is string terminator null
	defer func() { 
		_, _ = readInt8FromBuff(buff) //discard last byte which is string terminator null
	}()
	err = binary.Read(buff, binary.LittleEndian, res)
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
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
		case UINT_T:
			res, err = readUInt32FromBuff(dataBuff)
			if err != nil {
				return nil, err
			}
		case LONG_T:
			res, err = readInt64FromBuff(dataBuff)
			if err != nil {
				return nil, err
			}
		case ULONG_T:
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
					return res, fmt.Errorf("error reading string array element type: %v", err)
				}
			}
			res = ss
		case CAP_T:
			cap, err := readInt32FromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading capability arg: %v", err)
			}
			if int(cap)<len(capabilities) {
				res = capabilities[cap]
			} else {
				res = string(cap)
			}
		case SYSCALL_T:
			sc, err := readInt32FromBuff(dataBuff)
			if err != nil {
				return res, fmt.Errorf("error reading syscall arg: %v", err)
			}
			if int(sc)<len(eventNames) {
				res = eventNames[sc]
			} else {
				res = string(sc)
			}
		default:
			//if we don't recognize the arg type, we can't parse the rest of the buffer
			return nil, fmt.Errorf("error unknown arg type %v", at)
	}
	return res, nil
}