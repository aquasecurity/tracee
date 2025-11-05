package detectors

import (
	"context"
	"errors"
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&HookedSyscall{})
}

// HookedSyscall detects when a syscall table entry points to an unexpected address,
// indicating a potential syscall hook (common rootkit technique).
type HookedSyscall struct {
	logger              detection.Logger
	dataStores          datastores.Registry
	reportedHooks       *lru.Cache[int32, uint64] // syscall_id -> address
	maxSysCallTableSize int
}

func (d *HookedSyscall) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "DRV-002",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "syscall_table_check",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       "symbol",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "syscall",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "hooked_syscall_detector",
			Description: "Syscall table hook detected (potential rootkit)",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "syscall", Type: "const char*"},
				{Name: "address", Type: "const char*"},
				{Name: "function", Type: "const char*"},
				{Name: "owner", Type: "const char*"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Syscall Table Hooking Detected",
			Description: "A syscall table entry has been modified to point to an unexpected address, indicating potential syscall hooking by a rootkit",
			Severity:    v1beta1.Severity_CRITICAL,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1014",
					Name: "Rootkit",
				},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *HookedSyscall) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores
	d.maxSysCallTableSize = 500

	var err error
	d.reportedHooks, err = lru.New[int32, uint64](d.maxSysCallTableSize)
	if err != nil {
		return err
	}

	d.logger.Debugw("HookedSyscall detector initialized")
	return nil
}

func (d *HookedSyscall) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	symbolStore := d.dataStores.KernelSymbols()
	if symbolStore == nil {
		return nil, errors.New("kernel_symbols datastore not available")
	}

	syscallStore := d.dataStores.Syscalls()
	if syscallStore == nil {
		return nil, errors.New("syscall datastore not available")
	}

	// Get syscall ID and address from the event
	syscallId, err := v1beta1.GetDataSafe[int32](event, "syscall_id")
	if err != nil {
		return nil, fmt.Errorf("error parsing syscall_id: %w", err)
	}

	address, err := v1beta1.GetDataSafe[uint64](event, "syscall_address")
	if err != nil {
		return nil, fmt.Errorf("error parsing syscall_address: %w", err)
	}

	// Cache hit: don't report the same syscall_id and address again
	alreadyReportedAddress, found := d.reportedHooks.Get(syscallId)
	if found && alreadyReportedAddress == address {
		return nil, nil // Already reported this hook
	}

	// Update cache with new or changed hook
	d.reportedHooks.Add(syscallId, address)

	// Convert syscall_id to syscall name using the SyscallStore
	syscallName, err := syscallStore.GetSyscallName(syscallId)
	if err != nil {
		// If not found or not a syscall, use empty string (matches original behavior)
		syscallName = ""
	}

	hexAddress := fmt.Sprintf("%x", address)

	// Try to resolve the hooked address to a symbol
	hookedSymbols, err := symbolStore.ResolveSymbolByAddress(address)
	if err != nil || len(hookedSymbols) == 0 {
		// Can't resolve symbol, but still report the hook with empty function/owner
		data := []*v1beta1.EventValue{
			v1beta1.NewStringValue("syscall", syscallName),
			v1beta1.NewStringValue("address", hexAddress),
			v1beta1.NewStringValue("function", ""),
			v1beta1.NewStringValue("owner", ""),
		}
		return []detection.DetectorOutput{{Data: data}}, nil
	}

	// Create an event for each symbol at this address (multiple can exist)
	// This matches the original behavior: multiple events, one per symbol
	outputs := make([]detection.DetectorOutput, 0, len(hookedSymbols))
	for _, symbol := range hookedSymbols {
		data := []*v1beta1.EventValue{
			v1beta1.NewStringValue("syscall", syscallName),
			v1beta1.NewStringValue("address", hexAddress),
			v1beta1.NewStringValue("function", symbol.Name),
			v1beta1.NewStringValue("owner", symbol.Module),
		}
		outputs = append(outputs, detection.DetectorOutput{Data: data})

		d.logger.Debugw("Syscall hook detected",
			"syscall", syscallName,
			"syscall_id", syscallId,
			"address", hexAddress,
			"hook_function", symbol.Name,
			"module", symbol.Module)
	}

	return outputs, nil
}

func (d *HookedSyscall) Close() error {
	d.logger.Debugw("HookedSyscall detector closed")
	return nil
}
