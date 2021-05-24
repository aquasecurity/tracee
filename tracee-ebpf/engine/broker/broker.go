package broker

import (
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/event"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/stats"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/streamers"
	"github.com/orcaman/concurrent-map"
	"strconv"
	"sync/atomic"
)

type Broker struct {
	nextAvailStreamerId uint64
	Streamers           cmap.ConcurrentMap
	ChanEvents          <-chan event.Event
}

func (b *Broker) Register(streamer streamers.Streamer) error {
	b.nextAvailStreamerId = atomic.AddUint64(&b.nextAvailStreamerId, 1)
	if ok := b.Streamers.SetIfAbsent(strconv.FormatUint(b.nextAvailStreamerId, 10), streamer); !ok {
		return fmt.Errorf("failed to subscribe streamer")
	}
	streamer.SetId(b.nextAvailStreamerId)
	streamer.Preamble()
	return nil
}

func (b *Broker) Unregister(id uint64) (streamers.Streamer, error) {
	s, ok := b.Streamers.Get(strconv.FormatUint(id, 10))
	if !ok {
		return nil, fmt.Errorf("not existing subscriber: %v", id)
	}
	b.Streamers.Remove(strconv.FormatUint(id, 10))
	return s.(streamers.Streamer), nil
}

func (b *Broker) Start(stats *stats.Store) error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for printEvent := range b.ChanEvents {
			stats.EventCounter.Increment()
			cb := func(key string, v interface{}) {
				v.(streamers.Streamer).Stream(&printEvent)
			}
			b.Streamers.IterCb(cb)
		}
	}()
	return nil
	// TODO
	//return errc, nil
}

func (b *Broker) Stop(stats *stats.Store) {
	cb := func(key string, v interface{}) {
		v.(streamers.Streamer).Epilogue(*stats)
		v.(streamers.Streamer).Close()
	}
	b.Streamers.IterCb(cb)
	b.Streamers.Clear()
}
