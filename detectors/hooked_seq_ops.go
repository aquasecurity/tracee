package detectors

import (
	"context"
	"errors"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&HookedSeqOps{})
}

// Struct names for the interfaces HookedSeqOps checks for hooks
// The show,start,next and stop operation function pointers will be checked for each of those
var netSeqOps = [6]string{
	"tcp4_seq_ops",
	"tcp6_seq_ops",
	"udp_seq_ops",
	"udp6_seq_ops",
	"raw_seq_ops",
	"raw6_seq_ops",
}

var netSeqOpsFuncs = [4]string{
	"show",
	"start",
	"next",
	"stop",
}

// HookedSeqOps detects when network seq_ops function pointers are hooked,
// indicating potential network traffic hiding by rootkits.
type HookedSeqOps struct {
	logger     detection.Logger
	dataStores datastores.Registry
}

func (d *HookedSeqOps) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "DRV-003",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "print_net_seq_ops",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       "symbol",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "hooked_seq_ops_detector",
			Description: "Network seq_ops function pointer hooking detected (potential rootkit)",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "hooked_seq_ops_detector", Type: "map[string]trace.HookedSymbolData"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Network Seq_ops Hooking Detected",
			Description: "Network seq_ops function pointers have been modified to point to unexpected addresses, indicating potential network traffic hiding by a rootkit",
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

func (d *HookedSeqOps) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dataStores = params.DataStores

	d.logger.Debugw("HookedSeqOps detector initialized")
	return nil
}

func (d *HookedSeqOps) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	symbolStore := d.dataStores.KernelSymbols()
	if symbolStore == nil {
		return nil, errors.New("symbol datastore not available")
	}

	// Get the net_seq_ops array from the event
	var seqOpsArr []uint64
	for _, data := range event.Data {
		if data.Name == "net_seq_ops" {
			if arr := data.GetUInt64Array(); arr != nil {
				seqOpsArr = arr.Value
				break
			}
		}
	}

	if len(seqOpsArr) < 1 {
		return nil, nil // No data to process
	}

	// Build the map of hooked seq_ops
	// The map format is: "tcp4_seq_ops_show" -> {SymbolName: "fake_show", ModuleOwner: "rootkit"}
	hookedSeqOps := make(map[string]*v1beta1.HookedSymbolData)

	for i, addr := range seqOpsArr {
		// text segment check is done in kernel, marked as 0
		if addr == 0 {
			continue
		}

		// Resolve the address to a symbol
		symbols, err := symbolStore.ResolveSymbolByAddress(addr)
		if err != nil || len(symbols) == 0 {
			// Can't resolve symbol, skip this one
			d.logger.Debugw("Failed to resolve seq_ops address", "address", addr, "error", err)
			continue
		}

		// Indexing logic is as follows:
		// For an address at index i:
		//   - seqOpsStruct = netSeqOps[i/4]
		//   - seqOpsFunc = netSeqOpsFuncs[i%4]
		seqOpsStruct, seqOpsFunc := getSeqOpsSymbols(i)
		if seqOpsStruct == "" || seqOpsFunc == "" {
			d.logger.Errorw("failed to get seq ops symbols - this should not happen", "index", i)
			continue
		}

		// Use the first symbol (GetPotentiallyHiddenSymbolByAddr[0] in original)
		hookingFunction := symbols[0]

		// Create the map key and value
		key := seqOpsStruct + "_" + seqOpsFunc
		hookedSeqOps[key] = &v1beta1.HookedSymbolData{
			SymbolName:  hookingFunction.Name,
			ModuleOwner: hookingFunction.Module,
		}
	}

	// If no hooks found, don't produce an event
	if len(hookedSeqOps) == 0 {
		return nil, nil
	}

	// Create the output data
	data := []*v1beta1.EventValue{
		{
			Name: "hooked_seq_ops_detector",
			Value: &v1beta1.EventValue_HookedSeqOps{
				HookedSeqOps: &v1beta1.HookedSeqOps{
					Value: hookedSeqOps,
				},
			},
		},
	}

	d.logger.Debugw("Network seq_ops hooks detected",
		"hook_count", len(hookedSeqOps))

	return []detection.DetectorOutput{{Data: data}}, nil
}

func (d *HookedSeqOps) Close() error {
	d.logger.Debugw("HookedSeqOps detector closed")
	return nil
}

// getSeqOpsSymbols returns the seq_ops struct name and function name for a given index
func getSeqOpsSymbols(index int) (seqOpsStruct string, seqOpsFunc string) {
	if index < 0 || index/4 >= len(netSeqOps) || index%4 >= len(netSeqOpsFuncs) {
		return "", ""
	}

	seqOpsStruct = netSeqOps[index/4]
	seqOpsFunc = netSeqOpsFuncs[index%4]

	if seqOpsStruct == "" || seqOpsFunc == "" {
		return "", ""
	}

	return seqOpsStruct, seqOpsFunc
}
