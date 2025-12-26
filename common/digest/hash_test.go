package digest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
)

func computeFileHashOld(file *os.File) (string, error) {
	h := sha256.New()

	_, err := io.Copy(h, file)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func TestCurrentHashCompatibility(t *testing.T) {
	files := []string{
		"/usr/bin/uname",
		"/usr/bin/date",
	}

	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			t.Fatal(err)
		}

		h1, err := digest.ComputeFileHash(file)
		require.NoError(t, err)
		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		h2, err := computeFileHashOld(file)
		require.NoError(t, err)
		err = file.Close()
		require.NoError(t, err)
		assert.Equal(t, h1, h2)
	}
}

func TestComputeFileHashAtPath(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		// Create a temporary test file
		tempFile, err := os.CreateTemp("", "test_hash_*")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())

		testContent := "test content for hashing"
		_, err = tempFile.WriteString(testContent)
		require.NoError(t, err)
		err = tempFile.Close()
		require.NoError(t, err)

		// Test ComputeFileHashAtPath
		hash, err := digest.ComputeFileHashAtPath(tempFile.Name())
		require.NoError(t, err)
		require.NotEmpty(t, hash)

		// Verify hash is correct by computing manually
		file, err := os.Open(tempFile.Name())
		require.NoError(t, err)
		defer file.Close()

		expectedHash, err := digest.ComputeFileHash(file)
		require.NoError(t, err)

		assert.Equal(t, expectedHash, hash)
	})

	t.Run("non-existent file", func(t *testing.T) {
		hash, err := digest.ComputeFileHashAtPath("/non/existent/file")
		assert.Error(t, err)
		assert.Empty(t, hash)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("directory instead of file", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test_dir_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		hash, err := digest.ComputeFileHashAtPath(tempDir)
		assert.Error(t, err)
		assert.Empty(t, hash)
	})

	t.Run("empty file", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "test_empty_*")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		err = tempFile.Close()
		require.NoError(t, err)

		hash, err := digest.ComputeFileHashAtPath(tempFile.Name())
		require.NoError(t, err)
		require.NotEmpty(t, hash)

		// Empty file should have a specific SHA256 hash
		expectedEmptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		assert.Equal(t, expectedEmptyHash, hash)
	})
}

// Mock path resolver for testing cache functionality
type mockPathResolver struct {
	hostPaths map[string]string // map[absolutePath_mountNS] = hostPath
	errors    map[string]error  // map[absolutePath_mountNS] = error to return
}

func newMockPathResolver() *mockPathResolver {
	return &mockPathResolver{
		hostPaths: make(map[string]string),
		errors:    make(map[string]error),
	}
}

func (m *mockPathResolver) GetHostAbsPath(absolutePath string, mountNS uint32) (string, error) {
	key := fmt.Sprintf("%s/ns/%d", absolutePath, mountNS)
	if err, exists := m.errors[key]; exists {
		return "", err
	}
	if hostPath, exists := m.hostPaths[key]; exists {
		return hostPath, nil
	}
	// Default: return the same path
	return absolutePath, nil
}

func (m *mockPathResolver) addMapping(absolutePath string, mountNS uint32, hostPath string) {
	key := fmt.Sprintf("%s/ns/%d", absolutePath, mountNS)
	m.hostPaths[key] = hostPath
}

func (m *mockPathResolver) addError(absolutePath string, mountNS uint32, err error) {
	key := fmt.Sprintf("%s/ns/%d", absolutePath, mountNS)
	m.errors[key] = err
}

func TestCalcHashesOption_String(t *testing.T) {
	tests := []struct {
		name     string
		option   digest.CalcHashesOption
		expected string
	}{
		{"none", digest.CalcHashesNone, "none"},
		{"inode", digest.CalcHashesInode, "inode"},
		{"dev-inode", digest.CalcHashesDevInode, "dev-inode"},
		{"digest-inode", digest.CalcHashesDigestInode, "digest-inode"},
		{"unknown", digest.CalcHashesOption(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.option.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewCache(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		resolver := newMockPathResolver()
		cache, err := digest.NewCache(digest.CalcHashesInode, resolver)

		assert.NoError(t, err)
		assert.NotNil(t, cache)
	})

	t.Run("all cache modes", func(t *testing.T) {
		resolver := newMockPathResolver()
		modes := []digest.CalcHashesOption{
			digest.CalcHashesNone,
			digest.CalcHashesInode,
			digest.CalcHashesDevInode,
			digest.CalcHashesDigestInode,
		}

		for _, mode := range modes {
			t.Run(mode.String(), func(t *testing.T) {
				cache, err := digest.NewCache(mode, resolver)
				assert.NoError(t, err)
				assert.NotNil(t, cache)
			})
		}
	})
}

func TestKey_NewKey(t *testing.T) {
	t.Run("basic key creation", func(t *testing.T) {
		key := digest.NewKey("/path/to/file", 12345)
		assert.Equal(t, "/path/to/file", key.Pathname())
		assert.Equal(t, uint32(12345), key.MountNS())
	})

	t.Run("key with device option", func(t *testing.T) {
		key := digest.NewKey("/path/to/file", 12345, digest.WithDevice(67890))
		assert.Equal(t, "/path/to/file", key.Pathname())
		assert.Equal(t, uint32(12345), key.MountNS())
	})

	t.Run("key with inode option", func(t *testing.T) {
		key := digest.NewKey("/path/to/file", 12345, digest.WithInode(98765, 1234567890))
		assert.Equal(t, "/path/to/file", key.Pathname())
		assert.Equal(t, uint32(12345), key.MountNS())
	})

	t.Run("key with digest option", func(t *testing.T) {
		key := digest.NewKey("/path/to/file", 12345, digest.WithDigest("sha256:abc123"))
		assert.Equal(t, "/path/to/file", key.Pathname())
		assert.Equal(t, uint32(12345), key.MountNS())
	})

	t.Run("key with all options", func(t *testing.T) {
		key := digest.NewKey("/path/to/file", 12345,
			digest.WithDevice(67890),
			digest.WithInode(98765, 1234567890),
			digest.WithDigest("sha256:abc123"))
		assert.Equal(t, "/path/to/file", key.Pathname())
		assert.Equal(t, uint32(12345), key.MountNS())
	})
}

func TestKey_KeyMethods(t *testing.T) {
	key := digest.NewKey("/path/to/file", 12345,
		digest.WithDevice(67890),
		digest.WithInode(98765, 1234567890),
		digest.WithDigest("sha256:abc123"))

	t.Run("InodeKey", func(t *testing.T) {
		expected := "1234567890:98765"
		assert.Equal(t, expected, key.InodeKey())
	})

	t.Run("DeviceKey", func(t *testing.T) {
		expected := "67890:1234567890:98765"
		assert.Equal(t, expected, key.DeviceKey())
	})

	t.Run("DigestKey", func(t *testing.T) {
		expected := "sha256:abc123:1234567890:98765"
		assert.Equal(t, expected, key.DigestKey())
	})

	t.Run("DigestKey with empty digest", func(t *testing.T) {
		emptyDigestKey := digest.NewKey("/path", 123, digest.WithInode(456, 789))
		assert.Equal(t, "", emptyDigestKey.DigestKey())
	})

	t.Run("WithDigest empty string becomes host", func(t *testing.T) {
		hostKey := digest.NewKey("/path", 123,
			digest.WithInode(456, 789),
			digest.WithDigest(""))
		expected := "host:789:456"
		assert.Equal(t, expected, hostKey.DigestKey())
	})
}

func TestCache_Get(t *testing.T) {
	// Create a temporary test file for hashing
	tempFile, err := os.CreateTemp("", "test_cache_*")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	testContent := "test content for cache testing"
	_, err = tempFile.WriteString(testContent)
	require.NoError(t, err)
	err = tempFile.Close()
	require.NoError(t, err)

	// Calculate expected hash
	expectedHash, err := digest.ComputeFileHashAtPath(tempFile.Name())
	require.NoError(t, err)

	t.Run("inode mode cache miss and hit", func(t *testing.T) {
		resolver := newMockPathResolver()
		resolver.addMapping("/container/path", 12345, tempFile.Name())

		cache, err := digest.NewCache(digest.CalcHashesInode, resolver)
		require.NoError(t, err)

		key := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 1234567890))

		// First call - cache miss
		hash1, err := cache.Get(&key)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash1)

		// Second call - cache hit (same ctime)
		hash2, err := cache.Get(&key)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash2)
		assert.Equal(t, hash1, hash2)
	})

	t.Run("dev-inode mode", func(t *testing.T) {
		resolver := newMockPathResolver()
		resolver.addMapping("/container/path", 12345, tempFile.Name())

		cache, err := digest.NewCache(digest.CalcHashesDevInode, resolver)
		require.NoError(t, err)

		key := digest.NewKey("/container/path", 12345,
			digest.WithDevice(67890),
			digest.WithInode(98765, 1234567890))

		hash, err := cache.Get(&key)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash)
	})

	t.Run("digest-inode mode", func(t *testing.T) {
		resolver := newMockPathResolver()
		resolver.addMapping("/container/path", 12345, tempFile.Name())

		cache, err := digest.NewCache(digest.CalcHashesDigestInode, resolver)
		require.NoError(t, err)

		key := digest.NewKey("/container/path", 12345,
			digest.WithInode(98765, 1234567890),
			digest.WithDigest("sha256:abc123"))

		hash, err := cache.Get(&key)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash)
	})

	t.Run("cache invalidation on ctime change", func(t *testing.T) {
		resolver := newMockPathResolver()
		resolver.addMapping("/container/path", 12345, tempFile.Name())

		cache, err := digest.NewCache(digest.CalcHashesInode, resolver)
		require.NoError(t, err)

		// First key with ctime 1
		key1 := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 1))
		hash1, err := cache.Get(&key1)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash1)

		// Second key with different ctime should trigger recalculation
		key2 := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 2))
		hash2, err := cache.Get(&key2)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash, hash2) // Same file, same hash
	})

	t.Run("error cases", func(t *testing.T) {
		resolver := newMockPathResolver()

		cache, err := digest.NewCache(digest.CalcHashesInode, resolver)
		require.NoError(t, err)

		t.Run("empty key", func(t *testing.T) {
			// Empty key only occurs in digest mode when no digest is provided
			cache, err := digest.NewCache(digest.CalcHashesDigestInode, resolver)
			require.NoError(t, err)

			key := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 1234567890))
			// No digest set, DigestKey() returns empty string
			_, err = cache.Get(&key)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "empty key given")
		})

		t.Run("unknown calc hash mode", func(t *testing.T) {
			// This is harder to test directly since getKeyByExecHashMode is internal
			// But we can test it indirectly by using CalcHashesNone
			cache, err := digest.NewCache(digest.CalcHashesNone, resolver)
			require.NoError(t, err)

			key := digest.NewKey("/path", 123, digest.WithInode(456, 789))
			_, err = cache.Get(&key)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unknown calc hash option type")
		})

		t.Run("path resolver error", func(t *testing.T) {
			resolverErr := errors.New("path resolution failed")
			resolver.addError("/container/path", 12345, resolverErr)

			key := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 1234567890))
			_, err := cache.Get(&key)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "path resolution failed")
		})

		t.Run("file hash computation error", func(t *testing.T) {
			// Create a new resolver for this test to avoid conflicts
			newResolver := newMockPathResolver()
			newResolver.addMapping("/container/path", 12345, "/non/existent/file")

			newCache, err := digest.NewCache(digest.CalcHashesInode, newResolver)
			require.NoError(t, err)

			key := digest.NewKey("/container/path", 12345, digest.WithInode(98765, 1234567890))
			hash, err := newCache.Get(&key)
			// Should return empty hash and no error (error is handled internally)
			assert.Equal(t, "", hash)
			assert.NoError(t, err)
		})
	})
}
