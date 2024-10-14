package ebpf

import (
	"context"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventStatsValues struct {
	attempts uint64
	failures uint64
}

// countPerfEventWrites logs the number of attempts and failures to write to the perf event buffer
// for each event type, as well as the total attempts and failures.
func (t *Tracee) countPerfEventWrites(ctx context.Context) {
	logger.Debugw("Starting countPerfEventWrites goroutine")
	defer logger.Debugw("Stopped countPerfEventWrites goroutine")

	evtsCountsBPFMap, err := t.bpfModule.GetMap("events_stats")
	if err != nil {
		logger.Errorw("Failed to get events_stats map", "error", err)
		return
	}

	evtStatZero := eventStatsValues{}
	for _, id := range t.policyManager.EventsSelected() {
		key := uint32(id)
		err := evtsCountsBPFMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&evtStatZero))
		if err != nil {
			logger.Errorw("Failed to update events_stats map", "error", err)
		}
	}

	totalAttempts := counter.NewCounter(0)
	totalFailures := counter.NewCounter(0)
	evtsCounts := make(map[uint32]eventStatsValues)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Get the counts of each event from the BPF map into a hashmap
			iter := evtsCountsBPFMap.Iterator()
			for iter.Next() {
				key := binary.LittleEndian.Uint32(iter.Key())
				value, err := evtsCountsBPFMap.GetValue(unsafe.Pointer(&key))
				if err != nil {
					logger.Errorw("Failed to get value from events_stats map", "error", err)
					continue
				}

				evtsCounts[key] = eventStatsValues{
					attempts: binary.LittleEndian.Uint64(value[0:8]),
					failures: binary.LittleEndian.Uint64(value[8:16]),
				}
			}

			// Get the counts of each event from the hashmap into a slice (key value pairs)
			// and calculate the total count
			keyValsAttempts := make([]interface{}, 0, len(evtsCounts)*2+1)
			keyValsFailures := make([]interface{}, 0, len(evtsCounts)*2+1)
			totalAttempts.Set(0)
			totalFailures.Set(0)
			for k, v := range evtsCounts {
				keyValsAttempts = append(keyValsAttempts,
					events.Core.GetDefinitionByID(events.ID(k)).GetName(),
					v.attempts,
				)
				keyValsFailures = append(keyValsFailures,
					events.Core.GetDefinitionByID(events.ID(k)).GetName(),
					v.failures,
				)

				err := totalAttempts.Increment(v.attempts)
				if err != nil {
					logger.Errorw("Failed to increment total counter", "error", err)
				}
				err = totalFailures.Increment(v.failures)
				if err != nil {
					logger.Errorw("Failed to increment total failures counter", "error", err)
				}
			}

			// Log the counts
			keyValsAttempts = append(keyValsAttempts, "total", totalAttempts.Get())
			logger.Infow("Event sending attempts", keyValsAttempts...)
			keyValsFailures = append(keyValsFailures, "total", totalFailures.Get())
			logger.Infow("Event sending failures", keyValsFailures...)
			t.stats.BPFPerfEventWriteAttempts.Set(totalAttempts.Get())
			t.stats.BPFPerfEventWriteFailures.Set(totalFailures.Get())
		}
	}
}
