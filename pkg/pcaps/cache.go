package pcaps

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
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
				logger.Debug("could not evict a pcap cache item")
				return
			}

			err := item.pcapWriter.Flush()
			if err != nil {
				logger.Error("Flushing pcap", "error", err)
			}
			err = item.pcapFile.Close()
			if err != nil {
				logger.Error("Closing file", "error", err)
			}
		})

	return &PcapCache{
		itemCache: cache,
		itemType:  itemType,
	}, utils.ErrorFuncName(err)
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
			return nil, utils.ErrorFuncName(err)
		}
		p.itemCache.Add(getItemIndexFromEvent(event, p.itemType), new)
		item = new
	} else {
		// return the cached item
		item, ok = i.(*Pcap)
		if !ok {
			return nil, fmt.Errorf("unexpected item type in pcap cache")
		}
	}

	return item, nil
}

func (p *PcapCache) destroy() error {

	for _, k := range p.itemCache.Keys() {
		switch key := k.(type) {
		case *Pcap:
			err := key.close()
			if err != nil {
				logger.Error("Closing file", "error", err)
			}
		default:
			return fmt.Errorf("wrong key type in pcap cache")
		}
	}
	p.itemCache.Purge()

	return nil
}
