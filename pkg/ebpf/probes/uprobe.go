package probes

import (
	"errors"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/elf"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

var (
	ErrFileAccess   = errors.New("error accessing file")
	ErrFileAnalysis = errors.New("error analyzing file")
)

type UprobeType uint8

const (
	Uprobe UprobeType = iota
	Uretprobe
)

var uprobeTypeNames = map[UprobeType]string{
	Uprobe:    "Uprobe",
	Uretprobe: "Uretprobe",
}

func (t UprobeType) String() string {
	if name, ok := uprobeTypeNames[t]; ok {
		return name
	}

	return fmt.Sprintf("Invalid uprobe type %d", t)
}

type GenericUprobe interface {
	GetProbeType() UprobeType
	GetEvent() UprobeEvent
	GetProgramName() string
}

// FixedUprobe represents a uprobe attached to a specific binary at a fixed location.
type FixedUprobe struct {
	ProbeCompatibility
	probeType   UprobeType
	programName string         // eBPF program to execute when uprobe triggered
	binaryPath  string         // ELF file path to attach uprobe to
	event       UprobeEvent    // ELF binary symbol to attach uprobe to
	bpfLinks    []*bpf.BPFLink // attach/detach thread-safety guaranteed by the ProbeGroup big lock
}

// NewFixedUprobe creates a new fixed uprobe that will be attached to a single binary.
func NewFixedUprobe(probeType UprobeType, progName string, binPath string, event UprobeEvent) *FixedUprobe {
	return &FixedUprobe{
		probeType:   probeType,
		programName: progName,
		binaryPath:  binPath,
		event:       event,
	}
}

// NewFixedUprobeWithCompatibility creates a new fixed uprobe with compatibility.
func NewFixedUprobeWithCompatibility(probeType UprobeType, progName string, binPath string, event UprobeEvent, compatibility *ProbeCompatibility) *FixedUprobe {
	return &FixedUprobe{
		ProbeCompatibility: *compatibility,
		probeType:          probeType,
		programName:        progName,
		binaryPath:         binPath,
		event:              event,
	}
}

func (p *FixedUprobe) GetProbeType() UprobeType {
	return p.probeType
}

func (p *FixedUprobe) GetEvent() UprobeEvent {
	return p.event
}

func (p *FixedUprobe) GetProgramName() string {
	return p.programName
}

// IsAttached returns true if the uprobe is currently attached.
func (p *FixedUprobe) IsAttached() bool {
	return len(p.bpfLinks) > 0
}

func (p *FixedUprobe) attach(module *bpf.Module, args ...interface{}) error {
	if p.IsAttached() {
		return nil // already attached, it is ok to call attach again
	}

	if module == nil {
		return errfmt.Errorf("incorrect arguments for event: %s", p.event)
	}

	links, err := attachToFileFixed(p, module, p.binaryPath)
	if err != nil {
		return errfmt.WrapError(err)
	}

	p.bpfLinks = links

	return nil
}

func (p *FixedUprobe) detach(args ...interface{}) error {
	if !p.IsAttached() {
		return nil // already detached, it is ok to call detach again
	}

	var allErrors []error
	for _, link := range p.bpfLinks {
		if err := link.Destroy(); err != nil {
			allErrors = append(allErrors, err)
		}
	}

	if len(allErrors) > 0 {
		return errfmt.Errorf("failed to detach %d link(s) for event %s: %v",
			len(allErrors), p.event, allErrors)
	}

	p.bpfLinks = nil // NOTE: needed so a new call to detach() works

	return nil
}

func (p *FixedUprobe) autoload(module *bpf.Module, autoload bool) error {
	return enableDisableAutoload(module, p.programName, autoload)
}

func (p *FixedUprobe) load(module *bpf.Module) (bool, error) {
	prog, err := module.GetProgram(p.programName)
	if err != nil {
		return false, errfmt.WrapError(err)
	}

	// Check if already loaded
	if prog.FileDescriptor() > 0 {
		return false, nil
	}

	// Load and verify FD
	_, err = prog.LoadUprobe()
	if err != nil {
		return false, errfmt.WrapError(err)
	}

	if prog.FileDescriptor() <= 0 {
		return false, errfmt.Errorf("program loaded but has no valid file descriptor")
	}

	return true, nil
}

// attachToFileFixed attaches a FixedUprobe to a file - only supports UprobeEventSymbol
func attachToFileFixed(p *FixedUprobe, module *bpf.Module, binaryPath string) ([]*bpf.BPFLink, error) {
	prog, err := module.GetProgram(p.GetProgramName())
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// FixedUprobe only supports UprobeEventSymbol
	event, ok := p.GetEvent().(UprobeEventSymbol)
	if !ok {
		return nil, errfmt.Errorf("FixedUprobe only supports UprobeEventSymbol, got %T", p.GetEvent())
	}

	// Create ELF analyzer for symbol lookup
	wantedSymbols := []elf.WantedSymbol{elf.NewPlainSymbolName(string(event))}
	ea, err := elf.NewElfAnalyzer(binaryPath, wantedSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to create ELF analyzer for %s: %w: %w", binaryPath, ErrFileAccess, err)
	}
	defer func() {
		if err := ea.Close(); err != nil {
			logger.Warnw("error closing file", "path", binaryPath, "error", err)
		}
	}()

	switch p.GetProbeType() {
	case Uprobe, Uretprobe:
		// Get attachment offset for symbol
		offset, err := ea.GetSymbolOffset(string(event))
		if err != nil {
			return nil, fmt.Errorf("%w: error finding %s function offset: %w", ErrFileAnalysis, p.GetEvent().String(), err)
		}

		// Perform the attachment
		var link *bpf.BPFLink
		if p.GetProbeType() == Uprobe {
			link, err = prog.AttachUprobe(-1, binaryPath, offset)
		} else {
			link, err = prog.AttachURetprobe(-1, binaryPath, offset)
		}
		if err != nil {
			return nil, fmt.Errorf("error attaching uprobe on %s (0x%x): %w", p.GetEvent().String(), offset, err)
		}
		return []*bpf.BPFLink{link}, nil

	default:
		return nil, errfmt.Errorf("FixedUprobe only supports Uprobe and Uretprobe probe types, got %s", p.GetProbeType().String())
	}
}
