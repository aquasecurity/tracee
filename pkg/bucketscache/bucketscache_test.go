package bucketscache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/bucketscache"
)

func TestBucketsCache(t *testing.T) {
	t.Parallel()

	var cache bucketscache.BucketsCache
	cache.Init(5)
	cache.AddBucketItem(1, 32)
	cache.AddBucketItem(1, 32)
	cache.AddBucketItem(1, 32)
	cache.AddBucketItem(1, 32)
	cache.AddBucketItem(1, 32)
	cache.AddBucketItem(1, 33) // should not do anything
	bucket := cache.GetBucket(1)
	assert.ElementsMatch(t, bucket, []uint32{32, 32, 32, 32, 32})
	cache.ForceAddBucketItem(1, 33) // force 33 to index 0
	bucket = cache.GetBucket(1)
	assert.ElementsMatch(t, bucket, []uint32{33, 32, 32, 32, 32})

	// get non existing bucket
	bucket = cache.GetBucket(2)
	assert.Empty(t, bucket)

	// get existing bucket item
	item, err := cache.GetBucketItem(1, 0)
	require.NoError(t, err)
	assert.Equal(t, item, uint32(33))

	// get non existing bucket item
	_, err = cache.GetBucketItem(2, 0)
	assert.Equal(t, err.Error(), bucketscache.NoSuchItem(2, 0).Error())
}
