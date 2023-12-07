package bucketscache

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type BucketsCache struct {
	buckets      map[uint32][]uint32
	bucketLimit  int
	bucketsMutex *sync.RWMutex
}

func (c *BucketsCache) Init(bucketLimit int) {
	c.bucketLimit = bucketLimit
	c.buckets = make(map[uint32][]uint32)
	c.bucketsMutex = new(sync.RWMutex)
}

func (c *BucketsCache) GetBucket(key uint32) []uint32 {
	c.bucketsMutex.RLock()
	defer c.bucketsMutex.RUnlock()

	if orig, ok := c.buckets[key]; ok {
		b := make([]uint32, len(orig))
		copy(b, orig)
		return b
	}

	return nil
}

func (c *BucketsCache) GetBucketItem(key uint32, index int) (uint32, error) {
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

func (c *BucketsCache) AddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, false)
}

func (c *BucketsCache) ForceAddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, true)
}

func (c *BucketsCache) addBucketItem(key uint32, value uint32, force bool) {
	c.bucketsMutex.RLock()
	b, exists := c.buckets[key]
	c.bucketsMutex.RUnlock()
	if !exists {
		c.bucketsMutex.Lock()
		c.buckets[key] = make([]uint32, 0, c.bucketLimit)
		b = c.buckets[key]
		c.bucketsMutex.Unlock()
	}
	if len(b) >= c.bucketLimit {
		if !force {
			return
		}
		b[0] = value
	} else {
		c.bucketsMutex.Lock()
		c.buckets[key] = append(b, value)
		c.bucketsMutex.Unlock()
	}
}

func NoSuchItem(key uint32, index int) error {
	return errfmt.Errorf("no such item in cache at key: %d, index: %d", key, index)
}
