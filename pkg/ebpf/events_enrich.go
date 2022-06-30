package ebpf

import (
	gocontext "context"
	"sync"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	enrichResultQueueSize = 1000
	enrichmentQueueSize   = 10000
)

func (t *Tracee) enrichContainerEvents(ctx gocontext.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
	type enrichResult struct {
		cgroupId uint64
		result   runtime.ContainerMetadata
		err      error
	}

	queues := make(map[uint64]chan *trace.Event) // cgroupId and queues
	queuesMutex := sync.RWMutex{}
	attempted := make(map[uint64]*sync.Mutex)                  // cgroupId and enrichment attempt expressed as transaction lock
	attemptedMutex := sync.RWMutex{}                           // big lock for attempted map
	enriches := make(chan enrichResult, enrichResultQueueSize) // small buffer to reduce chance for blocking
	//queues that are no longer used. we don't want to close on receiving side so it will mark queues as stale and sender can close
	staleQueues := make(map[uint64]chan *trace.Event)
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	done := make(chan struct{}, 1)

	go func() {
		defer close(out)
		defer close(errc)
		for {
			select {
			case <-ctx.Done():
				done <- struct{}{}
				return
			case event := <-in:
				cgroupId := uint64(event.CgroupID)
				// cgroup_mkdir event: need the cgroupId from its argument
				if event.EventID == int(events.CgroupMkdir) {
					cgroupId, _ = parse.ArgUint64Val(event, "cgroup_id")
				}
				// cgroup_rmdir: need to clean attempt so cgroupId can be reused
				if event.EventID == int(events.CgroupRmdir) {
					cgroupId, _ = parse.ArgUint64Val(event, "cgroup_id")
					attemptedMutex.Lock()
					delete(attempted, cgroupId)
					attemptedMutex.Unlock()
				}
				// non container event and not cgroup_mkdir (or the event already enriched) skip per cgroupId caching
				if (event.ContainerID == "" && event.EventID != int(events.CgroupMkdir)) || event.ContainerImage != "" {
					// enrichment attempt is being done, or has failed, so do not try it again
					attemptedMutex.RLock()
					if _, ok := attempted[cgroupId]; ok {
						// wait transaction (cache flush) to finish so cached events and this one are ordered
						attempted[cgroupId].Lock()
						out <- event
						attempted[cgroupId].Unlock()
						attemptedMutex.RUnlock()
						continue
					}
					attemptedMutex.RUnlock()
					out <- event // some events might not have an attempted map
					continue
				} else {
					//if the container queue has not been created - create the container queue and invoke to enrich query
					queuesMutex.RLock()
					_, exists := queues[cgroupId]
					queuesMutex.RUnlock()
					if !exists {
						queuesMutex.Lock()
						queues[cgroupId] = make(chan *trace.Event, enrichmentQueueSize)
						queuesMutex.Unlock()

						go func() {
							metadata, err := t.containers.EnrichCgroupInfo(cgroupId)
							enriches <- enrichResult{cgroupId, metadata, err}
						}()
					}
					queuesMutex.RLock()
					queue, ok := queues[cgroupId]
					queuesMutex.RUnlock()
					if ok {
						//if queue still exists send as usual
						queue <- event
					} else {
						//if not, get the enriched data and handle the stale queue
						info := t.containers.GetCgroupInfo(cgroupId)
						queuesMutex.RLock()
						queue = staleQueues[cgroupId]
						queuesMutex.RUnlock()

						//probably empty but just to make sure
						for evt := range queue {
							enrichEvent(evt, info.Container)
							out <- evt
						}

						enrichEvent(event, info.Container)

						close(queue)
						queuesMutex.Lock()
						delete(staleQueues, cgroupId)
						queuesMutex.Unlock()
						out <- event
					}
				}
			}
		}
	}()

	go func() {
		for enrich := range enriches {
			cgroupId := enrich.cgroupId
			mutex := &sync.Mutex{}
			mutex.Lock() // place already acquired mutex in the attempted map
			attemptedMutex.Lock()
			attempted[cgroupId] = mutex // now attempted[cgroupId] is a transaction, only happens once and has begun
			attemptedMutex.Unlock()
			queuesMutex.RLock()
			queue := queues[cgroupId]
			queuesMutex.RUnlock()
			if enrich.err != nil {
				//only send error if it's not a non-existing cgroup error
				if enrich.err.Error() != "no cgroup to enrich" {
					t.handleError(enrich.err)
				}

				for evt := range queue {
					select {
					case out <- evt:
					case <-done:
						return
					}

					//at this point no new events should enter this queue, since the attempt was marked
					//we need this break condition, otherwise we will wait for new events forever
					if len(queue) < 1 {
						break
					}
				}
			} else {
				//go through the queue and inject the enrichment data that was missing during decoding
				for evt := range queue {
					if evt.ContainerID != "" {
						enrichEvent(evt, enrich.result)
					}
					select {
					case out <- evt:
					case <-done:
						return
					}

					//at this point no new events should enter this queue, since the attempt was marked
					//we need this break condition, otherwise we will wait for new events forever
					if len(queue) < 1 {
						break
					}
				}
			}
			mutex.Unlock() // end of transaction

			//after enrichment was done and all events were processed we can close and delete the channel from the map
			//subsequent events will be enriched during decoding

			queuesMutex.Lock()
			delete(queues, cgroupId)
			staleQueues[cgroupId] = queue
			queuesMutex.Unlock()
		}
	}()

	return out, errc
}

func enrichEvent(evt *trace.Event, enrichData runtime.ContainerMetadata) {
	evt.ContainerImage = enrichData.Image
	evt.ContainerName = enrichData.Name
	evt.PodName = enrichData.Pod.Name
	evt.PodNamespace = enrichData.Pod.Namespace
	evt.PodUID = enrichData.Pod.UID
}
