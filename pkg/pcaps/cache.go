package pcaps

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// PcapCache is an intermediate LRU cache in between Pcap and Pcaps
type PcapCache struct {
	itemCache *lru.Cache[string, *Pcap]
	itemType  PcapType
}

func newPcapCache(itemType PcapType) (*PcapCache, error) {
	cache, err := lru.NewWithEvict(
		pcapsToCache,
		func(_ string, item *Pcap,
		) {
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
		n, err := NewPcap(event, p.itemType)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		p.itemCache.Add(getItemIndexFromEvent(event, p.itemType), n)
		item = n
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
	for _, key := range p.itemCache.Keys() {
		item, _ := p.itemCache.Get(key)
		if err := item.close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}
	p.itemCache.Purge()

	return nil
}
