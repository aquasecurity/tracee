package ebpf

import (
	gocontext "context"
	"sync"

	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
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
func (t *Tracee) enrichContainerEvents(ctx gocontext.Context, in <-chan *trace.Event,
) (
	chan *trace.Event, chan error,
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
		result runtime.ContainerMetadata
		err    error
	}

	// big lock
	bLock := sync.RWMutex{}
	// pipeline channels
	out := make(chan *trace.Event, t.config.PipelineChannelSize)
	errc := make(chan error, 1)
	// state machine for enrichment
	enrichDone := make(map[uint64]bool)
	enrichInfo := make(map[uint64]*enrichResult)
	// 1 queue per cgroupId
	queues := make(map[uint64]chan *trace.Event)
	// scheduler queues
	queueReady := make(chan uint64, queueReadySize)
	queueClean := make(chan *trace.Event, queueReadySize)

	// queues map writer
	go func() {
		defer close(out)
		defer close(errc)
		for { // enqueue events
			select {
			case event := <-in:
				if event == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}
				eventID := events.ID(event.EventID)
				// send out irrelevant events (non container or already enriched), don't skip the cgroup lifecycle events
				if (event.Container.ID == "" || event.Container.Name != "") &&
					eventID != events.CgroupMkdir &&
					eventID != events.CgroupRmdir {
					out <- event
					continue
				}
				cgroupId := uint64(event.CgroupID)
				// CgroupMkdir: pick EventID from the event itself
				if eventID == events.CgroupMkdir {
					// avoid sending irrelevant cgroups
					isHid, err := isCgroupEventInHid(event, t.containers)
					if err != nil {
						logger.Errorw("cgroup_mkdir event skipped enrichment: couldn't get cgroup hid", "error", err)
						out <- event
						continue
					}
					if !isHid {
						out <- event
						continue
					}
					cgroupId, err = parse.ArgVal[uint64](event.Args, "cgroup_id")
					if err != nil {
						logger.Errorw("cgroup_mkdir event failed to trigger enrichment: couldn't get cgroup_id", "error", err, "event_name", event.EventName)
						out <- event
						continue
					}
				}
				// CgroupRmdir: clean up remaining events and maps
				if eventID == events.CgroupRmdir {
					queueClean <- event
					continue
				}
				// make sure a queue channel exists for this cgroupId
				bLock.Lock()
				if _, ok := queues[cgroupId]; !ok {
					queues[cgroupId] = make(chan *trace.Event, contQueueSize)

					go func(cgroupId uint64) {
						metadata, err := t.containers.EnrichCgroupInfo(cgroupId)
						bLock.Lock()
						enrichInfo[cgroupId] = &enrichResult{metadata, err}
						enrichDone[cgroupId] = true
						logger.Debugw("async enrich request in pipeline done", "cgroup_id", cgroupId)
						bLock.Unlock()
					}(cgroupId)
				}
				bLock.Unlock() // give parallel enrichment routine a chance!
				bLock.RLock()
				// enqueue the event and schedule the operation
				queues[cgroupId] <- event
				bLock.RUnlock()
				queueReady <- cgroupId
			case <-ctx.Done():
				return
			}
		}
	}()

	// queues map reader
	go func() {
		for { // de-queue events
			select {
			case cgroupId := <-queueReady: // queue for received cgroupId is ready
				logger.Debugw("triggered enrich check in enrich queue", "cgroup_id", cgroupId)
				bLock.RLock()
				if !enrichDone[cgroupId] {
					// re-schedule the operation if queue is not enriched
					queueReady <- cgroupId
					logger.Debugw("rescheduled enrich trigger in enrich queue", "cgroup_id", cgroupId)
				} else {
					// de-queue event if queue is enriched
					if _, ok := queues[cgroupId]; ok {
						event := <-queues[cgroupId]
						if event == nil {
							continue // might happen during initialization (ctrl+c seg faults)
						}
						eventID := events.ID(event.EventID)
						if eventID == events.CgroupMkdir {
							// only one cgroup_mkdir should make it here
							// report enrich success or error once
							i := enrichInfo[cgroupId]
							if i.err == nil {
								logger.Debugw("done enriching in enrich queue", "cgroup_id", cgroupId)
							} else {
								logger.Errorw("failed enriching in enrich queue", "error", i.err, "cgroup_id", cgroupId)
							}
						}
						// check if not enriched, and only enrich regular non cgroup related events
						if event.Container.Name == "" && eventID != events.CgroupMkdir && eventID != events.CgroupRmdir {
							// event is not enriched: enrich if enrichment worked
							i := enrichInfo[cgroupId]
							if i.err == nil {
								enrichEvent(event, i.result)
							}
						}
						out <- event
					} // TODO: place a unlikely to happen error in the printer
				}
				bLock.RUnlock()
			// cleanup
			case <-ctx.Done():
				return
			}
		}
	}()

	// queues cleaner
	go func() {
		for {
			select {
			case event := <-queueClean:
				bLock.Lock()
				cgroupId, err := parse.ArgVal[uint64](event.Args, "cgroup_id")
				if err != nil {
					logger.Errorw("cgroup_rmdir event failed to trigger enrich queue clean: couldn't get cgroup_id", "error", err, "event_name", event.EventName)
					out <- event
					continue
				}
				logger.Debugw("triggered enrich queue clean", "cgroup_id", cgroupId)
				if queue, ok := queues[cgroupId]; ok {
					// if queue is still full reschedule cleanup
					if len(queue) > 0 {
						queueClean <- event
						logger.Debugw("rescheduled enrich queue clean", "cgroup_id", cgroupId)
					} else {
						close(queue)
						// start queue cleanup
						delete(enrichDone, cgroupId)
						delete(enrichInfo, cgroupId)
						delete(queues, cgroupId)
						out <- event
					}
				}
				bLock.Unlock()
				logger.Debugw("enrich queue clean done", "cgroup_id", cgroupId)

			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

func enrichEvent(evt *trace.Event, enrichData runtime.ContainerMetadata) {
	evt.Container = trace.Container{
		ID:          enrichData.ContainerId,
		ImageName:   enrichData.Image,
		ImageDigest: enrichData.ImageDigest,
		Name:        enrichData.Name,
	}
	evt.Kubernetes = trace.Kubernetes{
		PodName:      enrichData.Pod.Name,
		PodNamespace: enrichData.Pod.Namespace,
		PodUID:       enrichData.Pod.UID,
	}
}

// isCgroupEventInHid checks if cgroup event is relevant for deriving container event in its hierarchy id.
// in tracee we only care about containers inside the cpuset controller, as such other hierarchy ids will lead
// to a failed query.
func isCgroupEventInHid(event *trace.Event, cts *containers.Containers) (bool, error) {
	if cts.GetCgroupVersion() == cgroup.CgroupVersion2 {
		return true, nil
	}
	hierarchyID, err := parse.ArgVal[uint32](event.Args, "hierarchy_id")
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	return cts.GetDefaultCgroupHierarchyID() == int(hierarchyID), nil
}
