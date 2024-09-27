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

// countPerfEventWrites counts the number of times each event is attempted
// to be written to the perf buffer.
func (t *Tracee) countPerfEventWrites(ctx context.Context) {
	logger.Debugw("Starting countPerfEventWrites goroutine")
	defer logger.Debugw("Stopped countPerfEventWrites goroutine")

	evtsCountsBPFMap, err := t.bpfModule.GetMap("event_counts")
	if err != nil {
		logger.Errorw("Failed to get event_counts map", "error", err)
		return
	}

	for _, id := range t.policyManager.EventsSelected() {
		key := uint32(id)
		value := uint64(0)
		err := evtsCountsBPFMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
		if err != nil {
			logger.Errorw("Failed to update event_counts map", "error", err)
		}
	}

	total := counter.NewCounter(0)
	evtsCounts := make(map[uint32]uint64)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			iter := evtsCountsBPFMap.Iterator()
			for iter.Next() {
				key := binary.LittleEndian.Uint32(iter.Key())
				value, err := evtsCountsBPFMap.GetValue(unsafe.Pointer(&key))
				if err != nil {
					logger.Errorw("Failed to get value from event_counts map", "error", err)
					continue
				}

				evtsCounts[key] = binary.LittleEndian.Uint64(value)
			}

			total.Set(0)
			for k, v := range evtsCounts {
				if v == 0 {
					continue
				}
				err := total.Increment(v)
				if err != nil {
					logger.Errorw("Failed to increment total counter", "error", err)
				}

				logger.Debugw("Event sending attempts",
					"event", events.Core.GetDefinitionByID(events.ID(k)).GetName(),
					"count", v,
				)
			}

			logger.Debugw("Event sending attempts", "total", total.Get())
			t.stats.BPFPerfEventWrites.Set(total.Get())
		}
	}
}
