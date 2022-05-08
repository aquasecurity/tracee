package ebpf

import (
	gocontext "context"

	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/types/trace"
)

func (t *Tracee) enrichContainerEvents(ctx gocontext.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
	type enrichResult struct {
		cgroupId uint64
		result   runtime.ContainerMetadata
		err      error
	}

	queues := make(map[uint64]chan *trace.Event) //map between cgroupId and queues
	attempted := make(map[uint64]bool)           //map between cgroupId and enrichment attempt
	enriches := make(chan enrichResult, 10)      //this channel has a small buffer to reduce chance for blocking
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
				//if the event is the cgroup_mkdir event we need the cgroupId from it's argument
				if event.EventID == int(CgroupMkdirEventID) {
					cgroupId, _ = getEventArgUint64Val(event, "cgroup_id")
				}
				//if the event is a cgroup_rmdir we need to clean the attempt entry so the cgroupId can be reused
				if event.EventID == int(CgroupRmdirEventID) {
					cgroupId, _ = getEventArgUint64Val(event, "cgroup_id")
					delete(attempted, cgroupId)
				}
				//if non container event and not cgroup_mkdir or the event is already enriched, skip this stage
				if (event.ContainerID == "" && event.EventID != int(CgroupMkdirEventID)) || event.ContainerImage != "" || attempted[uint64(cgroupId)] {
					out <- event
					continue
				} else {
					//if the container queue has not been created - create the container queue and invoke the enrich query
					if _, ok := queues[cgroupId]; !ok {
						queues[cgroupId] = make(chan *trace.Event, 1000)

						go func() {
							metadata, err := t.containers.EnrichCgroupInfo(cgroupId)
							enriches <- enrichResult{cgroupId, metadata, err}
						}()
					}
					queues[cgroupId] <- event
				}
			}
		}
	}()

	go func() {
		for enrich := range enriches {
			cgroupId := enrich.cgroupId
			//mark the query as finished, it should not be attempted again and no new events should enter it's queue
			attempted[cgroupId] = true
			if enrich.err != nil {
				//only send error if it's not a non existing cgroup error
				if enrich.err.Error() != "no cgroup to enrich" {
					t.handleError(enrich.err)
				}
				for evt := range queues[cgroupId] {
					select {
					case out <- evt:
					case <-done:
						return
					}

					//at this point no new events should enter this queue, since the attempt was marked
					//we need this break condition, otherwise we will wait for new events forever
					if len(queues[cgroupId]) < 1 {
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
				for evt := range queues[cgroupId] {
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
					if len(queues[cgroupId]) < 1 {
						break
					}
				}
			}

			//after enrichment was done and all events were processed we can close and delete the channel from the map
			//subsequent events will be enriched during decoding
			close(queues[cgroupId])
			delete(queues, cgroupId)
		}
	}()

	return out, errc
}
