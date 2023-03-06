package pcaps

import (
	lru "github.com/hashicorp/golang-lru"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// PcapCache is an intermediate LRU cache in between Pcap and Pcaps
type PcapCache struct {
	itemCache *lru.Cache
	itemType  PcapType
}

func newPcapCache(itemType PcapType) (*PcapCache, error) {

	cache, err := lru.NewWithEvict(
		pcapsToCache,
		func(_ interface{}, value interface{},
		) {
			// sync and close pcap file on evict
			item, ok := value.(*Pcap)
			if !ok {
				logger.Debugw("Could not evict a pcap cache item")
				return
			}

			if err := item.pcapWriter.Flush(); err != nil {
				logger.Errorw("Flushing pcap", "error", err)
			}
			if err := item.pcapFile.Close(); err != nil {
				logger.Errorw("Closing file", "error", err)
			}
		})

	return &PcapCache{
		itemCache: cache,
		itemType:  itemType,
	}, errfmt.WrapError(err)
}

func (p *PcapCache) get(event *trace.Event) (*Pcap, error) {
	var ok bool
	var item *Pcap
	var i interface{}

	i, ok = p.itemCache.Get(getItemIndexFromEvent(event, p.itemType))
	if !ok {
		// create an item and return it
		new, err := NewPcap(event, p.itemType)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		p.itemCache.Add(getItemIndexFromEvent(event, p.itemType), new)
		item = new
	} else {
		// return the cached item
		item, ok = i.(*Pcap)
		if !ok {
			return nil, errfmt.Errorf("unexpected item type in pcap cache")
		}
	}

	return item, nil
}

func (p *PcapCache) destroy() error {

	for _, k := range p.itemCache.Keys() {
		switch key := k.(type) {
		case *Pcap:
			if err := key.close(); err != nil {
				logger.Errorw("Closing file", "error", err)
			}
		default:
			return errfmt.Errorf("wrong key type in pcap cache")
		}
	}
	p.itemCache.Purge()

	return nil
}
