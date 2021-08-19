package tracee

type bucketsCache struct {
	buckets     map[uint32][]uint32
	bucketLimit int
	Null        uint32
}

func (c *bucketsCache) Init(bucketLimit int) {
	c.bucketLimit = bucketLimit
	c.buckets = make(map[uint32][]uint32)
	c.Null = 0
}

func (c *bucketsCache) GetBucket(key uint32) []uint32 {
	return c.buckets[key]
}

func (c *bucketsCache) GetBucketItem(key uint32, index int) uint32 {
	b, exists := c.buckets[key]
	if !exists {
		return c.Null
	}
	if index >= len(b) {
		return c.Null
	}
	return b[index]
}

func (c *bucketsCache) AddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, false)
}

func (c *bucketsCache) ForceAddBucketItem(key uint32, value uint32) {
	c.addBucketItem(key, value, true)
}

func (c *bucketsCache) addBucketItem(key uint32, value uint32, force bool) {
	b, exists := c.buckets[key]
	if !exists {
		c.buckets[key] = make([]uint32, 0, c.bucketLimit)
		b = c.buckets[key]
	}
	if len(b) >= c.bucketLimit {
		if force {
			b[0] = value
		} else {
			return
		}
	} else {
		c.buckets[key] = append(b, value)
	}
}
