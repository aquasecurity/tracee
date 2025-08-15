package bucketcache

import (
	"sync"

	"github.com/aquasecurity/tracee/common/errfmt"
)

type BucketCache struct {
	buckets      map[uint32][]uint32
	bucketLimit  int
	bucketsMutex *sync.RWMutex
}

func (c *BucketCache) Init(bucketLimit int) {
	c.bucketLimit = bucketLimit
	c.buckets = make(map[uint32][]uint32)
	c.bucketsMutex = new(sync.RWMutex)
}

func (c *BucketCache) GetBucket(key uint32) []uint32 {
	c.bucketsMutex.RLock()
	defer c.bucketsMutex.RUnlock()

	if orig, ok := c.buckets[key]; ok {
		b := make([]uint32, len(orig))
		copy(b, orig)
		return b
	}

	return nil
}

func (c *BucketCache) GetBucketItem(key uint32, index int) (uint32, error) {
	c.bucketsMutex.RLock()
	defer c.bucketsMutex.RUnlock()
	b, exists := c.buckets[key]
	if !exists {
		return 0, NoSuchItem(key, index)
	}
	if index >= len(b) {
		return 0, NoSuchItem(key, index)
	}
	return b[index], nil
}

func (c *BucketCache) AddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, false)
}

func (c *BucketCache) ForceAddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, true)
}

func (c *BucketCache) addBucketItem(key uint32, value uint32, force bool) {
	c.bucketsMutex.Lock()
	defer c.bucketsMutex.Unlock()

	b, exists := c.buckets[key]
	if !exists {
		c.buckets[key] = make([]uint32, 0, c.bucketLimit)
		b = c.buckets[key]
	}

	if len(b) >= c.bucketLimit {
		if !force {
			return
		}
		b[0] = value
	} else {
		c.buckets[key] = append(b, value)
	}
}

func NoSuchItem(key uint32, index int) error {
	return errfmt.Errorf("no such item in cache at key: %d, index: %d", key, index)
}
