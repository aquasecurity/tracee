package ebpf

import (
	"sync"

	"github.com/aquasecurity/tracee/common/cgroup"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/intern"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Producer:
//
// Each cgroupId gets its own channel of events. Events are enqueued and only
// de-dequed once the cgroupId was enriched OR has failed enrichment.
//
// [cgroupId #A]: queue of trace events for container described by cgroupId #A
// [cgroupId #B]: queue of trace events for container described by cgroupId #B
// [cgroupId #C]: queue of trace events for container described by cgroupId #C
// ...
//
// If the cgroupId channel does not exist it is created and an enrichment phase
// is triggered for that cgroupId. If the cgroup channel is not used after a
// specific period, it is removed.
//
// Consumer:
//
// In order to de-queue an event from its queue there is a scheduled operation
// to each queued event.
//
// queueReady: it is a simple scheduler of events using their cgroupId as index
//
// [cgroupId #A][cgroupId #B][cgroupId #C][#cgroupId #B][cgroupId #C]...
//
// One event is de-queued from queueReady only if its respective cgroupId has
// been enriched OR has failed enrichment.
//
// Observation:
//
// With this model, the pipeline will only block when one of these channels is
// full. In this case, pipeline will be blocked until this channel's cgroupId
// is enriched and its enqueued events are de-queued.
//

// enrichContainerEvents is a pipeline stage that enriches container events with metadata.
func (t *Tracee) enrichContainerEvents(in <-chan *events.PipelineEvent,
) (
	chan *events.PipelineEvent, chan error,
) {
	// Events may be enriched in the initial decode state, if the enrichment data has been
	// stored in the Containers structure. In that case, this pipeline stage will be
	// quickly skipped. The enrichment happens in a different stage to ensure that the
	// pipeline is not blocked by the container runtime calls.
	const (
		contQueueSize  = 10000  // max num of events queued per container
		queueReadySize = 100000 // max num of events queued in total
	)

	type enrichResult struct {
		result container.Container
		err    error
	}

	// big lock
	bLock := sync.RWMutex{}
	// pipeline channels
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	errc := make(chan error, 1)
	// state machine for enrichment
	enrichDone := make(map[uint64]bool)
	enrichInfo := make(map[uint64]*enrichResult)
	// 1 queue per cgroupId
	queues := make(map[uint64]chan *events.PipelineEvent)
	// scheduler queues
	queueReady := make(chan uint64, queueReadySize)
	queueClean := make(chan *events.PipelineEvent, queueReadySize)

	// wg tracks all goroutines that send to 'out' channel
	var wg sync.WaitGroup

	// writerDone is closed when the writer goroutine finishes draining the input
	// channel. Reader and cleaner goroutines watch this to enter drain mode.
	// NOTE: queueReady and queueClean are NEVER closed because they are used
	// bidirectionally (read + write-back for rescheduling). Sending to a closed
	// channel panics in Go, even inside a select with default. The writerDone
	// signal replaces channel closing as the shutdown mechanism.
	writerDone := make(chan struct{})

	// Name function for symbolic reference
	cleanupRoutine := func(out chan *events.PipelineEvent, errc chan error, wg *sync.WaitGroup) {
		wg.Wait()
		close(out)
		close(errc)
	}

	// processEvent handles a single event from the input channel. It is called
	// exclusively by the writer goroutine during its for-range loop, so
	// queueReady and queueClean are guaranteed to be open (writerDone has not
	// been closed yet). Non-blocking sends handle the case where internal
	// channels are full.
	processEvent := func(event *events.PipelineEvent) {
		if event == nil {
			return
		}
		eventID := event.EventID
		// send out irrelevant events (non container or already enriched), don't skip the cgroup lifecycle events
		if (event.Container.ID == "" || event.Container.Name != "") &&
			eventID != events.CgroupMkdir &&
			eventID != events.CgroupRmdir {
			out <- event
			return
		}
		cgroupId := uint64(event.CgroupID)
		// CgroupMkdir: pick EventID from the event itself
		if eventID == events.CgroupMkdir {
			// avoid sending irrelevant cgroups
			isHid, err := isCgroupEventInHid(event.Event, t.dataStoreRegistry.GetContainerManager())
			if err != nil {
				logger.Errorw("cgroup_mkdir event skipped enrichment: couldn't get cgroup hid", "error", err)
				out <- event
				return
			}
			if !isHid {
				out <- event
				return
			}
			cgroupId, err = parse.ArgVal[uint64](event.Args, "cgroup_id")
			if err != nil {
				logger.Errorw("cgroup_mkdir event failed to trigger enrichment: couldn't get cgroup_id", "error", err, "event_name", event.EventName)
				out <- event
				return
			}
		}
		// CgroupRmdir: queue for cleanup
		if eventID == events.CgroupRmdir {
			select {
			case queueClean <- event:
			default:
				// queueClean full, just send the event through
				out <- event
			}
			return
		}
		// make sure a queue channel exists for this cgroupId
		bLock.Lock()
		if _, ok := queues[cgroupId]; !ok {
			queues[cgroupId] = make(chan *events.PipelineEvent, contQueueSize)

			go func(cgroupId uint64) {
				metadata, err := t.dataStoreRegistry.GetContainerManager().EnrichCgroupInfo(cgroupId)
				bLock.Lock()
				enrichInfo[cgroupId] = &enrichResult{metadata, err}
				enrichDone[cgroupId] = true
				logger.Debugw("async enrich request in pipeline done", "cgroup_id", cgroupId)
				bLock.Unlock()
			}(cgroupId)
		}
		bLock.Unlock() // give parallel enrichment routine a chance!
		bLock.RLock()
		queue := queues[cgroupId]
		bLock.RUnlock()
		// enqueue the event and schedule the operation (channels are concurrent-safe)
		select {
		case queue <- event:
			select {
			case queueReady <- cgroupId:
			default:
				// queueReady full, drain the event we just added directly
				if e := <-queue; e != nil {
					out <- e
				}
			}
		default:
			// per-cgroup queue full, send event directly without enrichment
			out <- event
		}
	}

	// drainCgroupQueue drains all events from a single per-cgroup queue,
	// enriching them if enrichment data is available.
	drainCgroupQueue := func(cgroupId uint64, queue chan *events.PipelineEvent) {
		for len(queue) > 0 {
			event := <-queue
			if event == nil {
				continue
			}
			if enrichDone[cgroupId] {
				i := enrichInfo[cgroupId]
				if i != nil && i.err == nil && event.Container.Name == "" {
					enrichEvent(event.Event, i.result)
				}
			}
			out <- event
		}
	}

	//
	// Writer goroutine: reads from the pipeline input channel and distributes
	// events to internal queues via processEvent. Uses for-range so it
	// naturally drains all events when the upstream stage closes the input
	// channel. Signals reader/cleaner via writerDone when finished.
	//
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writerDone)

		for event := range in {
			processEvent(event)
		}
	}()

	//
	// Reader goroutine: de-queues events from per-cgroup queues and sends them
	// downstream after enrichment. Uses a select loop to multiplex between
	// queueReady (normal work) and writerDone (shutdown signal).
	//
	wg.Add(1)
	go func() {
		defer wg.Done()

		// dequeueAndEnrich processes a single cgroupId from queueReady.
		dequeueAndEnrich := func(cgroupId uint64) {
			bLock.RLock()
			defer bLock.RUnlock()

			if !enrichDone[cgroupId] {
				// Enrichment not done yet: reschedule (non-blocking to avoid
				// self-deadlock on full channel).
				select {
				case queueReady <- cgroupId:
					logger.Debugw("rescheduled enrich trigger in enrich queue", "cgroup_id", cgroupId)
				default:
					// queueReady full, drain the queue directly
					if queue, ok := queues[cgroupId]; ok {
						drainCgroupQueue(cgroupId, queue)
					}
				}
				return
			}

			// Enrichment done: de-queue one event
			queue, ok := queues[cgroupId]
			if !ok {
				return
			}
			select {
			case event := <-queue:
				if event == nil {
					return
				}
				eventID := event.EventID
				if eventID == events.CgroupMkdir {
					i := enrichInfo[cgroupId]
					if i.err == nil || i.result.ContainerId == "" {
						logger.Debugw("done enriching in enrich queue", "cgroup_id", cgroupId)
					} else {
						logger.Errorw("failed enriching in enrich queue", "error", i.err, "cgroup_id", cgroupId)
					}
				}
				if event.Container.Name == "" && eventID != events.CgroupMkdir && eventID != events.CgroupRmdir {
					i := enrichInfo[cgroupId]
					if i.err == nil {
						enrichEvent(event.Event, i.result)
					}
				}
				out <- event
			default:
				// Queue empty
			}
		}

		// Normal operation: multiplex between queueReady and writerDone.
		for {
			select {
			case cgroupId := <-queueReady:
				dequeueAndEnrich(cgroupId)
			case <-writerDone:
				// Writer finished: drain remaining items from queueReady
				// without rescheduling, then drain all per-cgroup queues.
				logger.Debugw("enrichContainerEvents: reader entering drain mode")
				for {
					select {
					case cgroupId := <-queueReady:
						bLock.RLock()
						if queue, ok := queues[cgroupId]; ok {
							drainCgroupQueue(cgroupId, queue)
						}
						bLock.RUnlock()
					default:
						// queueReady empty
						goto drainAllQueues
					}
				}
			}
		}
	drainAllQueues:
		logger.Debugw("enrichContainerEvents: draining all per-cgroup queues")
		bLock.RLock()
		for cgroupId, queue := range queues {
			drainCgroupQueue(cgroupId, queue)
		}
		bLock.RUnlock()
		logger.Debugw("enrichContainerEvents: per-cgroup queues drained")
	}()

	//
	// Cleaner goroutine: processes CgroupRmdir events to clean up per-cgroup
	// queues and enrichment state. Uses a select loop to multiplex between
	// queueClean (normal work) and writerDone (shutdown signal).
	//
	wg.Add(1)
	go func() {
		defer wg.Done()

		// processCleanEvent handles a single CgroupRmdir cleanup event.
		processCleanEvent := func(event *events.PipelineEvent, canReschedule bool) {
			bLock.Lock()
			defer bLock.Unlock()

			cgroupId, err := parse.ArgVal[uint64](event.Args, "cgroup_id")
			if err != nil {
				logger.Errorw("cgroup_rmdir event failed to trigger enrich queue clean: couldn't get cgroup_id", "error", err, "event_name", event.EventName)
				out <- event
				return
			}
			logger.Debugw("triggered enrich queue clean", "cgroup_id", cgroupId)
			queue, ok := queues[cgroupId]
			if !ok {
				out <- event
				return
			}
			if len(queue) > 0 && canReschedule {
				// Queue not empty: try to reschedule (non-blocking)
				select {
				case queueClean <- event:
					logger.Debugw("rescheduled enrich queue clean", "cgroup_id", cgroupId)
					return
				default:
					// Fall through to drain
				}
			}
			// Drain the queue, clean up, and send the rmdir event
			for len(queue) > 0 {
				queuedEvent := <-queue
				if queuedEvent != nil {
					out <- queuedEvent
				}
			}
			close(queue)
			delete(enrichDone, cgroupId)
			delete(enrichInfo, cgroupId)
			delete(queues, cgroupId)
			out <- event
			logger.Debugw("enrich queue clean done", "cgroup_id", cgroupId)
		}

		// Normal operation: multiplex between queueClean and writerDone.
		for {
			select {
			case event := <-queueClean:
				processCleanEvent(event, true)
			case <-writerDone:
				// Writer finished: drain remaining items from queueClean
				// without rescheduling.
				logger.Debugw("enrichContainerEvents: cleaner entering drain mode")
				for {
					select {
					case event := <-queueClean:
						processCleanEvent(event, false)
					default:
						logger.Debugw("enrichContainerEvents: cleaner finished")
						return
					}
				}
			}
		}
	}()

	// Wait for all sender goroutines to finish before closing channels
	go cleanupRoutine(out, errc, &wg)

	return out, errc
}

func enrichEvent(evt *trace.Event, cont container.Container) {
	evt.Container = trace.Container{
		ID:          intern.String(cont.ContainerId),
		ImageName:   intern.String(cont.Image),
		ImageDigest: intern.String(cont.ImageDigest),
		Name:        intern.String(cont.Name),
	}
	evt.Kubernetes = trace.Kubernetes{
		PodName:      intern.String(cont.Pod.Name),
		PodNamespace: intern.String(cont.Pod.Namespace),
		PodUID:       intern.String(cont.Pod.UID),
	}
}

// isCgroupEventInHid checks if cgroup event is relevant for deriving container event in its hierarchy id.
// in tracee we only care about containers inside the cpuset controller, as such other hierarchy ids will lead
// to a failed query.
func isCgroupEventInHid(event *trace.Event, cts *container.Manager) (bool, error) {
	if cts.GetCgroupVersion() == cgroup.CgroupVersion2 {
		return true, nil
	}
	hierarchyID, err := parse.ArgVal[uint32](event.Args, "hierarchy_id")
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	return cts.GetDefaultCgroupHierarchyID() == int(hierarchyID), nil
}
