package containers

import (
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/common/bucketcache"
)

func TestPathResolver_ResolveAbsolutePath(t *testing.T) {
	t.Parallel()

	t.Run("Mountns cache tests", func(t *testing.T) {
		type process struct {
			pid   uint32
			alive bool
		}
		testCases := []struct {
			Name          string
			nsProcesses   []process
			ExpectedError bool
		}{
			{
				Name: "Existing single process",
				nsProcesses: []process{
					{pid: 1, alive: true},
				},
				ExpectedError: false,
			},
			{
				Name: "Existing single process and dead children",
				nsProcesses: []process{
					{pid: 1, alive: true},
					{pid: 2, alive: false},
					{pid: 3, alive: false},
				},
				ExpectedError: false,
			},
			{
				Name: "Existing single child process",
				nsProcesses: []process{
					{pid: 1, alive: false},
					{pid: 2, alive: true},
					{pid: 1, alive: false},
				},
				ExpectedError: false,
			},
			{
				Name: "No living processes",
				nsProcesses: []process{
					{pid: 1, alive: false},
					{pid: 2, alive: false},
					{pid: 1, alive: false},
				},
				ExpectedError: true,
			},
			{
				Name:          "No processes in NS",
				nsProcesses:   []process{},
				ExpectedError: true,
			},
		}
		testMntNS := 1
		testFilePath := "/tmp/tmp.so"

		// capabilities.Initialize() call removed - no longer dropping capabilities // initialize capabilities
		// assert.NoError(t, err)

		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.Name, func(t *testing.T) {
				t.Parallel()

				// Initialize a mock for the os.Stat function
				mfs := fstest.MapFS{}
				bucket := bucketcache.BucketCache{}
				bucket.Init(20)
				for _, p := range testCase.nsProcesses {
					if p.alive {
						mfs[fmt.Sprintf("proc/%d/root/%s", p.pid, testFilePath)] = &fstest.MapFile{}
						bucket.AddBucketItem(uint32(testMntNS), p.pid)
					}
				}

				pres := InitContainerPathResolver(&bucket)
				pres.fs = mfs
				_, err := pres.GetHostAbsPath(testFilePath, uint32(testMntNS))
				if testCase.ExpectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("Path tests", func(t *testing.T) {
		testCases := []struct {
			name          string
			path          string
			pathExist     bool
			expectedError bool
		}{
			{
				name:          "Absolute path",
				path:          "/tmp/tmp.so",
				pathExist:     true,
				expectedError: false,
			},
			{
				name:          "Relative path",
				path:          "./temp.so",
				pathExist:     true,
				expectedError: true,
			},
			{
				name:          "Empty path",
				path:          "",
				pathExist:     true,
				expectedError: true,
			},
			{
				name:          "Illegal path",
				path:          "/tmp/tmp.so",
				pathExist:     false,
				expectedError: true,
			},
		}
		testMntNS := 1
		testPID := 1
		bucket := bucketcache.BucketCache{}
		bucket.Init(20)
		bucket.AddBucketItem(uint32(testMntNS), 1)
		for _, testCase := range testCases {
			testCase := testCase

			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				// Initialize a mock for the os.Stat function
				mfs := fstest.MapFS{}
				if testCase.pathExist {
					mfs[fmt.Sprintf("proc/%d/root/%s", testPID, testCase.path)] = &fstest.MapFile{}
				}

				pres := InitContainerPathResolver(&bucket)
				pres.fs = mfs
				_, err := pres.GetHostAbsPath(testCase.path, uint32(testMntNS))
				if testCase.expectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

func TestPathResolver_InputValidation(t *testing.T) {
	t.Parallel()

	bucket := bucketcache.BucketCache{}
	bucket.Init(20)
	pres := InitContainerPathResolver(&bucket)

	// Test invalid mount namespace
	_, err := pres.GetHostAbsPath("/test", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mount namespace ID")

	// Test non-absolute path
	_, err = pres.GetHostAbsPath("relative/path", 1234)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNonAbsolutePath)

	// Test empty path
	_, err = pres.GetHostAbsPath("", 1234)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNonAbsolutePath)
}

func TestPathResolver_ResolveLink(t *testing.T) {
	t.Parallel()

	// capabilities.Initialize() call removed - no longer dropping capabilities
	// require.NoError(t, err)

	t.Run("Input validation", func(t *testing.T) {
		bucket := bucketcache.BucketCache{}
		bucket.Init(20)
		pres := InitContainerPathResolver(&bucket)

		// Test invalid mount namespace
		_, err := pres.ResolveLink("/test", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid mount namespace ID")

		// Test non-absolute path
		_, err = pres.ResolveLink("relative/path", 1234)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNonAbsolutePath)
	})

	t.Run("Cache initialization and functionality", func(t *testing.T) {
		bucket := bucketcache.BucketCache{}
		bucket.Init(20)
		pres := InitContainerPathResolver(&bucket)

		// Cache should be properly initialized
		assert.NotNil(t, pres.symlinkCache, "symlink cache should be initialized")

		// Verify cache is working by adding and retrieving an entry
		if pres.symlinkCache != nil {
			pres.symlinkCache.Add("test-key", "test-value")
			value, exists := pres.symlinkCache.Get("test-key")
			assert.True(t, exists, "should find cached entry")
			assert.Equal(t, "test-value", value, "should return correct cached value")

			// Verify LRU eviction works with size limit
			for i := 0; i < 1025; i++ { // More than the 1024 limit
				pres.symlinkCache.Add(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i))
			}
			// Cache should not exceed its size limit
			assert.LessOrEqual(t, pres.symlinkCache.Len(), 1024, "cache should respect size limit")
		}
	})
}

func TestPathResolver_ResolveAllLinks(t *testing.T) {
	t.Parallel()

	bucket := bucketcache.BucketCache{}
	bucket.Init(20)
	pres := InitContainerPathResolver(&bucket)

	// Test input validation
	_, err := pres.ResolveAllLinks("/test", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mount namespace ID")

	_, err = pres.ResolveAllLinks("relative/path", 1234)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNonAbsolutePath)
}

func TestPathResolver_GetProcMounts(t *testing.T) {
	t.Parallel()

	bucket := bucketcache.BucketCache{}
	bucket.Init(20)
	pres := InitContainerPathResolver(&bucket)

	// Test input validation
	_, err := pres.GetProcMounts(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mount namespace ID")
}

func TestPathResolver_isWithinMountNS(t *testing.T) {
	t.Parallel()

	bucket := bucketcache.BucketCache{}
	bucket.Init(20)
	pres := InitContainerPathResolver(&bucket)

	testCases := []struct {
		name     string
		absPath  string
		nsRoot   string
		expected bool
	}{
		{
			name:     "Path within namespace",
			absPath:  "/proc/123/root/var/log/app.log",
			nsRoot:   "/proc/123/root",
			expected: true,
		},
		{
			name:     "Path exactly at namespace root",
			absPath:  "/proc/123/root",
			nsRoot:   "/proc/123/root",
			expected: true,
		},
		{
			name:     "Path outside namespace",
			absPath:  "/proc/456/root/var/log/app.log",
			nsRoot:   "/proc/123/root",
			expected: false,
		},
		{
			name:     "Path trying to escape with relative components",
			absPath:  "/proc/123/root/../456/root/file",
			nsRoot:   "/proc/123/root",
			expected: false,
		},
		{
			name:     "Path with similar prefix but different namespace",
			absPath:  "/proc/1234/root/file",
			nsRoot:   "/proc/123/root",
			expected: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := pres.isWithinMountNS(tc.absPath, tc.nsRoot)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPathResolver_isFileAccessible(t *testing.T) {
	t.Parallel()

	bucket := bucketcache.BucketCache{}
	bucket.Init(20)
	pres := InitContainerPathResolver(&bucket)

	// Test with a file that should exist
	assert.True(t, pres.isFileAccessible("/proc/self/stat"))

	// Test with a file that doesn't exist
	assert.False(t, pres.isFileAccessible("/nonexistent/file/path"))

	// Test with a directory (should be accessible but not readable as a file)
	assert.True(t, pres.isFileAccessible("/proc"))
}
