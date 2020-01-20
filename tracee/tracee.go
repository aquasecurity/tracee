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

// Tracee traces system calls and events using eBPF
type Tracee struct {
	config TraceConfig
	bpfProgramPath string
	bpfModule *bpf.Module
	bpfPerfMap *bpf.PerfMap
	eventsChannel chan []byte
	printer eventPrinter
}

// New creates a new Tracee instance based on the given TraceConfig
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
	if cfg.Syscalls == nil {
		cfg.Syscalls = make(map[string]bool)
	}
	for _, sc := range essentialSyscalls {
		cfg.Syscalls[sc] = true
	}
	if cfg.Sysevents == nil {
		cfg.Sysevents = make(map[string]bool)
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

	for _, sc := range essentialSyscalls {
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
	for _, se := range essentialSysevents {
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

func (t Tracee) processEvents() error {
	for {
		var err error
		var ctx context
		dataRaw := <-t.eventsChannel
		dataBuff := bytes.NewBuffer(dataRaw)
		err = readContextFromBuff(dataBuff, &ctx)
		if err != nil {
			return fmt.Errorf("error reading context for event: %v", err)
		}
		args := make([]interface{}, ctx.Argnum)
		for i:=0; i<int(ctx.Argnum); i++ {
			readArgFromBuff(dataBuff, &args[i])
		}
		t.printer.Print(ctx,args)
	}
	return nil
}

func readContextFromBuff(buff io.Reader, ctx *context) error {
	err := binary.Read(buff, binary.LittleEndian, ctx)
	return err
}

func readArgTypeFromBuff(dataBuff io.Reader, at *ArgType) error {
	err := binary.Read(dataBuff, binary.LittleEndian, at)
	return err
}

func readStringFromBuff(dataBuff io.Reader, s *string) error {
	var err error
	var size int32
	err = binary.Read(dataBuff, binary.LittleEndian, &size)
	if err != nil {
		return fmt.Errorf("error reading string string size: %v", err)
	}
	tmparg := make([]byte, size-1) //last byte is string terminator null
	err = binary.Read(dataBuff, binary.LittleEndian, tmparg)
	if err != nil {
		return fmt.Errorf("error reading string arg: %v", err)
	}
	*s = string(tmparg)
	var junk [1]byte
	_, _ = dataBuff.Read(junk[:]) //discard last byte which is string terminator null
	return nil
}
		
func readArgFromBuff(dataBuff io.Reader, arg *interface{}) error {
	var err error
	var at ArgType
	err = readArgTypeFromBuff(dataBuff, &at)
	if err != nil {
		return fmt.Errorf("error reading arg type: %v", err)
	}
	switch at {
		case INT_T:
			var tmparg int32
			err = binary.Read(dataBuff, binary.LittleEndian, &tmparg)
			if err != nil {
				return fmt.Errorf("error reading int arg: %v", err)
			}
			*arg = tmparg
		case UINT_T:
			var tmparg uint32
			err = binary.Read(dataBuff, binary.LittleEndian, &tmparg)
			if err != nil {
				return fmt.Errorf("error reading uint arg: %v", err)
			}
			*arg = tmparg
		case LONG_T:
			var tmparg int64
			err = binary.Read(dataBuff, binary.LittleEndian, &tmparg)
			if err != nil {
				return fmt.Errorf("error reading long arg: %v", err)
			}
			*arg = tmparg
		case ULONG_T:
			var tmparg int64
			err = binary.Read(dataBuff, binary.LittleEndian, &tmparg)
			if err != nil {
				return fmt.Errorf("error reading ulong arg: %v", err)
			}
			*arg = tmparg
		case STR_T:
			var s string
			readStringFromBuff(dataBuff, &s)
			*arg = s
		case STR_ARR_T:
			var tmparg []string
			// assuming there's at least one element in the array
			var et ArgType
			err = readArgTypeFromBuff(dataBuff, &et)
			if err != nil {
				return fmt.Errorf("error reading string array element type: %v", err)
			}
			for et != STR_ARR_T {
				var s string
				err = readStringFromBuff(dataBuff, &s)
				if err != nil {
					return fmt.Errorf("error reading string element: %v", err)
				}
				tmparg = append(tmparg, s)

				err = readArgTypeFromBuff(dataBuff, &et)
				if err != nil {
					return fmt.Errorf("error reading string array element type: %v", err)
				}
			}
			*arg = tmparg
	}
	return nil
}