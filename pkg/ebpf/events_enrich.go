package ebpf

import (
	gocontext "context"
	"sync"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/events/parsing"
	"github.com/aquasecurity/tracee/types/trace"
)

func (t *Tracee) enrichContainerEvents(ctx gocontext.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
	type enrichResult struct {
		cgroupId uint64
		result   runtime.ContainerMetadata
		err      error
	}

	queues := make(map[uint64]chan *trace.Event) // cgroupId and queues
	queuesMutex := sync.RWMutex{}
	attempted := make(map[uint64]*sync.Mutex) // cgroupId and enrichment attempt expressed as transaction lock
	attemptedMutex := sync.RWMutex{}          // big lock for attempted map
	enriches := make(chan enrichResult, 10)   // small buffer to reduce chance for blocking
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
				if event.EventID == int(CgroupMkdirEventID) {
					cgroupId, _ = parsing.GetEventArgUint64Val(event, "cgroup_id")
				}
				// cgroup_rmdir: need to clean attempt so cgroupId can be reused
				if event.EventID == int(CgroupRmdirEventID) {
					cgroupId, _ = parsing.GetEventArgUint64Val(event, "cgroup_id")
					attemptedMutex.Lock()
					delete(attempted, cgroupId)
					attemptedMutex.Unlock()
				}
				// non container event and not cgroup_mkdir (or the event already enriched) skip per cgroupId caching
				if (event.ContainerID == "" && event.EventID != int(CgroupMkdirEventID)) || event.ContainerImage != "" {
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
						queues[cgroupId] = make(chan *trace.Event, 1000)
						queuesMutex.Unlock()

						go func() {
							metadata, err := t.containers.EnrichCgroupInfo(cgroupId)
							enriches <- enrichResult{cgroupId, metadata, err}
						}()
					}
					queuesMutex.RLock()
					queues[cgroupId] <- event
					queuesMutex.RUnlock()
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
			if enrich.err != nil {
				//only send error if it's not a non-existing cgroup error
				if enrich.err.Error() != "no cgroup to enrich" {
					t.handleError(enrich.err)
				}
				queuesMutex.RLock()
				queue := queues[cgroupId]
				queuesMutex.RUnlock()
				for evt := range queues[cgroupId] {
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
				containerImage := enrich.result.Image
				containerName := enrich.result.Name
				podName := enrich.result.Pod.Name
				podNamespace := enrich.result.Pod.Namespace
				podUid := enrich.result.Pod.UID

				//go through the queue and inject the enrichment data that was missing during decoding
				queuesMutex.RLock()
				queue := queues[cgroupId]
				queuesMutex.RUnlock()
				for evt := range queue {
					if evt.ContainerID != "" {
						evt.ContainerImage = containerImage
						evt.ContainerName = containerName
						evt.PodName = podName
						evt.PodNamespace = podNamespace
						evt.PodUID = podUid
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
			close(queues[cgroupId])
			delete(queues, cgroupId)
			queuesMutex.Unlock()
		}
	}()

	return out, errc
}
