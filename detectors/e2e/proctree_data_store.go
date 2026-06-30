//go:build e2e

package e2e

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eProcessTreeDataStore{}) }

const (
	proctreeTesterName = "proctreetester"
)

// E2eProcessTreeDataStore is an e2e test detector for testing the process tree data store API.
type E2eProcessTreeDataStore struct {
	logger           detection.Logger
	processStore     datastores.ProcessStore
	holdTime         int
	eventCounter     int32    // atomic counter for sampling events to validate
	validationMod    int32    // validate every Nth event (0 = validate all)
	pendingEntityIds []uint32 // entity IDs collected from fast-path events, validated at checkpoints
	pendingMutex     sync.Mutex
}

func (d *E2eProcessTreeDataStore) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "PROCTREE_DATA_STORE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       datastores.Process,
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "PROCTREE_DATA_STORE",
			Description: "Instrumentation events E2E Tests: Process Tree Data Store Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eProcessTreeDataStore) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.processStore = params.DataStores.Processes()

	// Default to 5 seconds if not set
	d.holdTime = 5
	if holdTimeStr := os.Getenv("PROCTREE_HOLD_TIME"); holdTimeStr != "" {
		holdTime, err := strconv.Atoi(holdTimeStr)
		if err != nil {
			return err
		}
		d.holdTime = holdTime
	}

	// Configure event sampling for data store validation (PROCTREE_VALIDATION_MOD):
	//   0 = validate ALL events (most thorough, slowest, may drop events due to blocking)
	//   1 = validate every event (same as 0)
	//   N = validate every Nth event (e.g., 5 = validate events #5, #10, #15...)
	//   Default: 5 (balances throughput and validation - recommended for 16 event test)
	// Higher values = faster but less validation coverage
	// Lower values = more validation but risk blocking event pipeline
	d.validationMod = 5
	if modStr := os.Getenv("PROCTREE_VALIDATION_MOD"); modStr != "" {
		mod, err := strconv.Atoi(modStr)
		if err != nil {
			return err
		}
		d.validationMod = int32(mod)
	}

	d.logger.Debugw("E2eProcessTreeDataStore detector initialized",
		"holdTime", d.holdTime,
		"validationMod", d.validationMod)
	return nil
}

func (d *E2eProcessTreeDataStore) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Check that the event is from the tester
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || !strings.HasSuffix(pathname, proctreeTesterName) {
		return nil, nil
	}

	// Get process entity ID from the event
	var entityId uint32
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.UniqueId != nil {
		entityId = event.Workload.Process.UniqueId.Value
	}

	if entityId == 0 {
		d.logger.Warnw("process entity ID not found in event")
		return nil, nil
	}

	// Increment counter and decide whether to validate this event
	eventNum := atomic.AddInt32(&d.eventCounter, 1)
	shouldValidate := d.validationMod == 0 || (eventNum%d.validationMod) == 0

	if !shouldValidate {
		// Fast path: emit detection immediately without validation
		// Store the entity ID for later batch validation at the next checkpoint
		// This is safe because the data store might not be completely populated yet
		// for early events. We sample later events (when store is stable) for validation.
		d.pendingMutex.Lock()
		d.pendingEntityIds = append(d.pendingEntityIds, entityId)
		d.pendingMutex.Unlock()
		return detection.Detected(), nil
	}

	// Validation checkpoint: validate all pending events plus current event
	d.pendingMutex.Lock()
	entityIdsToValidate := append([]uint32{}, d.pendingEntityIds...) // copy pending IDs
	entityIdsToValidate = append(entityIdsToValidate, entityId)      // add current event
	d.pendingEntityIds = d.pendingEntityIds[:0]                      // clear pending list
	d.pendingMutex.Unlock()

	d.logger.Debugw("Validation checkpoint", "eventNum", eventNum, "validating", len(entityIdsToValidate), "entityIds", entityIdsToValidate)

	// Wait for the process tree to be updated
	time.Sleep(time.Duration(d.holdTime) * time.Second)

	maxRetries := 5
	validationFailures := 0

	// Validate all collected entity IDs (batch validation)
	for _, eid := range entityIdsToValidate {
		// Check process entries in the data store
		processPassed := false
		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				time.Sleep(100 * time.Millisecond * (1 << uint(attempt-1)))
			}

			processInfo, err := d.processStore.GetProcess(eid)
			if err != nil {
				d.logger.Debugw("attempt to get process failed", "entityId", eid, "attempt", attempt+1, "error", err)
				continue
			}

			// Verify basic process info exists
			if processInfo.UniqueId == eid {
				processPassed = true
				if attempt > 0 {
					d.logger.Infow("SUCCESS: checkProcess", "entityId", eid, "retries", attempt)
				}
				break
			}
		}
		if !processPassed {
			d.logger.Errorw("ERROR: checkProcess FAILED", "entityId", eid, "maxRetries", maxRetries)
			validationFailures++
			continue // Continue validating other entities
		}

		// Check lineage entries in the data store
		lineagePassed := false
		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				time.Sleep(100 * time.Millisecond * (1 << uint(attempt-1)))
			}

			ancestry, err := d.processStore.GetAncestry(eid, 10)
			if err != nil {
				d.logger.Debugw("attempt to get ancestry failed", "entityId", eid, "attempt", attempt+1, "error", err)
				continue
			}

			// Verify we got at least the process itself
			if len(ancestry) > 0 && ancestry[0].UniqueId == eid {
				lineagePassed = true
				if attempt > 0 {
					d.logger.Infow("SUCCESS: checkLineage", "entityId", eid, "retries", attempt)
				}
				break
			}
		}
		if !lineagePassed {
			d.logger.Errorw("ERROR: checkLineage FAILED", "entityId", eid, "maxRetries", maxRetries)
			validationFailures++
			continue // Continue validating other entities
		}
	}

	// Report validation results
	validatedCount := len(entityIdsToValidate)
	if validationFailures > 0 {
		d.logger.Errorw("Batch validation completed with failures",
			"validated", validatedCount,
			"failed", validationFailures,
			"passed", validatedCount-validationFailures)
		return nil, nil // No detection emitted if any validation failed
	}

	// All checks passed - emit detection
	d.logger.Infow("Batch validation passed", "validated", validatedCount, "entityIds", entityIdsToValidate)
	return detection.Detected(), nil
}

func (d *E2eProcessTreeDataStore) Close() error {
	d.logger.Debugw("E2eProcessTreeDataStore detector closed")
	return nil
}
