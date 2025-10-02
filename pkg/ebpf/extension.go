package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/common/errfmt"
)

// InitPhase represents different phases of Tracee initialization
// Extensions should implement a switch case in their Init method to handle different phases
type InitPhase int

const (
	// Early initialization phases
	InitPhaseStart         InitPhase = iota // At the start of Tracee Init
	InitPhaseCGroups                        // After cgroups filesystems initialization
	InitPhaseContainers                     // After containers initialization
	InitPhaseBPFProbes                      // After eBPF probes initialization
	InitPhaseKernelSymbols                  // After kernel symbols initialization
	InitPhaseBPFPrograms                    // After eBPF programs and maps initialization
	InitPhaseComplete                       // At the end of Tracee Init
)

// String returns the string representation of the InitPhase
func (p InitPhase) String() string {
	switch p {
	case InitPhaseStart:
		return "InitPhaseStart"
	case InitPhaseCGroups:
		return "InitPhaseCGroups"
	case InitPhaseContainers:
		return "InitPhaseContainers"
	case InitPhaseBPFProbes:
		return "InitPhaseBPFProbes"
	case InitPhaseKernelSymbols:
		return "InitPhaseKernelSymbols"
	case InitPhaseBPFPrograms:
		return "InitPhaseBPFPrograms"
	case InitPhaseComplete:
		return "InitPhaseComplete"
	default:
		return fmt.Sprintf("UNKNOWN_PHASE(%d)", int(p))
	}
}

// Extension interface for Tracee
type Extension interface {
	// Initialize the extension with a specific phase
	Init(ctx context.Context, t *Tracee, phase InitPhase) error
	// Run the extension
	Run(ctx context.Context, t *Tracee) error
	// Close the extension
	Close(t *Tracee) error
}

// Global Extension registry
var (
	extensionRegistry   []Extension
	extensionRegistryMu sync.RWMutex
)

// RegisterExtension registers a new extension and should
// be called during init() of each extension
func RegisterExtension(ext Extension) {
	extensionRegistryMu.Lock()
	defer extensionRegistryMu.Unlock()
	extensionRegistry = append(extensionRegistry, ext)
}

// Extensions manages the lifecycle of Tracee extensions
type Extensions struct{}

// NewExtensions creates a new Extensions manager
func NewExtensions() *Extensions {
	return &Extensions{}
}

// GetRegisteredExtensions returns all registered extensions from the global registry
func (e *Extensions) GetRegisteredExtensions() []Extension {
	extensionRegistryMu.RLock()
	defer extensionRegistryMu.RUnlock()
	if len(extensionRegistry) == 0 {
		return nil
	}
	// Return a copy to avoid race conditions
	result := make([]Extension, len(extensionRegistry))
	copy(result, extensionRegistry)
	return result
}

// InitExtensionsForPhase initializes all registered extensions with the specified phase
func (e *Extensions) InitExtensionsForPhase(ctx context.Context, t *Tracee, phase InitPhase) error {
	extensions := e.GetRegisteredExtensions()
	for i, ext := range extensions {
		if err := ext.Init(ctx, t, phase); err != nil {
			return errfmt.Errorf("failed to initialize extension %d during phase %s: %v", i, phase, err)
		}
	}
	return nil
}

// RunExtensions runs all registered extensions
func (e *Extensions) RunExtensions(ctx context.Context, t *Tracee) error {
	extensions := e.GetRegisteredExtensions()
	for i, ext := range extensions {
		if err := ext.Run(ctx, t); err != nil {
			return errfmt.Errorf("failed to run extension %d: %v", i, err)
		}
	}
	return nil
}

// CloseExtensions closes all registered extensions
func (e *Extensions) CloseExtensions(t *Tracee) error {
	extensions := e.GetRegisteredExtensions()
	for i, ext := range extensions {
		if err := ext.Close(t); err != nil {
			return errfmt.Errorf("failed to close extension %d: %v", i, err)
		}
	}
	return nil
}
