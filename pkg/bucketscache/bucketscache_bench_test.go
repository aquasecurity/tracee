package bucketscache

import (
	"sync"
	"testing"
)

type BucketsCacheWithOneLock struct {
	bc BucketsCache
}

func (c *BucketsCacheWithOneLock) Init(bucketLimit int) {
	c.bc.Init(bucketLimit)
}

func (c *BucketsCacheWithOneLock) addBucketItem(key uint32, value uint32, force bool) {
	c.bc.bucketsMutex.Lock()
	defer c.bc.bucketsMutex.Unlock()

	b, exists := c.bc.buckets[key]
	if !exists {
		c.bc.buckets[key] = make([]uint32, 0, c.bc.bucketLimit)
		b = c.bc.buckets[key]
	}

	if len(b) >= c.bc.bucketLimit {
		if !force {
			return
		}
		b[0] = value
	} else {
		c.bc.buckets[key] = append(b, value)
	}
}

func BenchmarkAddBucketItemCurrent(b *testing.B) {
	bc := &BucketsCache{}
	bc.Init(100)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1000 * b.N)
	for i := 0; i < 1000*b.N; i++ {
		go func() {
			<-start
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bc.addBucketItem(uint32(j), uint32(j), false)
			}
		}()
	}

	b.ResetTimer() // Start timing after setup
	close(start)
	wg.Wait()
	b.StopTimer()
}

func BenchmarkAddBucketItemWithOneLock(b *testing.B) {
	bc := &BucketsCacheWithOneLock{}
	bc.Init(100)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1000 * b.N)
	for i := 0; i < 1000*b.N; i++ {
		go func() {
			<-start
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bc.addBucketItem(uint32(j), uint32(j), false)
			}
		}()
	}

	b.ResetTimer() // Start timing after setup
	close(start)
	wg.Wait()
	b.StopTimer()
}
