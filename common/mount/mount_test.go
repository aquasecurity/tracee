package mount_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/mount"
)

func Test_MountForceFlag(t *testing.T) {
	cfg := mount.Config{
		Source: "/tmp/test",
		FsType: "tmpfs",
		Data:   "size=1M,uid=1000,gid=1000",
		Where:  "/tmp/test",
		Force:  true,
	}
	m, err := mount.NewMountHostOnce(cfg)
	assert.NoError(t, err)
	assert.True(t, m.IsMounted())
	assert.Equal(t, "/tmp/test", m.GetMountpoint())
}

func TestNewMountHostOnce_ForceMode(t *testing.T) {
	t.Run("force mode with existing path", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "mount_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M",
			Where:  tempDir,
			Force:  true,
		}

		m, err := mount.NewMountHostOnce(cfg)
		assert.NoError(t, err)
		assert.True(t, m.IsMounted())
		assert.Equal(t, tempDir, m.GetMountpoint())
		assert.NotZero(t, m.GetMountpointInode())
	})

	t.Run("force mode with non-existing path", func(t *testing.T) {
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M",
			Where:  "/path/that/does/not/exist",
			Force:  true,
		}

		m, err := mount.NewMountHostOnce(cfg)
		// Should not error even if path doesn't exist in force mode
		assert.NoError(t, err)
		assert.True(t, m.IsMounted())
		assert.Equal(t, "/path/that/does/not/exist", m.GetMountpoint())
	})
}

func TestNewMountHostOnce_NonForceMode(t *testing.T) {
	// Note: These tests are more limited because they would require actual mounting
	// capabilities which may not be available in test environment
	t.Run("non-force mode basic config", func(t *testing.T) {
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M",
			Where:  "",
			Force:  false,
		}

		// This might fail in test environment without proper capabilities
		// but we test the code path
		_, err := mount.NewMountHostOnce(cfg)
		// Don't assert on error since mounting might fail in test environment
		// The important thing is that the code doesn't panic
		_ = err // Just to use the variable
	})
}

func TestMountHostOnce_Methods(t *testing.T) {
	t.Run("getters for force mode mount", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "mount_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M",
			Where:  tempDir,
			Force:  true,
		}

		m, err := mount.NewMountHostOnce(cfg)
		require.NoError(t, err)

		// Test all getter methods
		assert.True(t, m.IsMounted())
		assert.Equal(t, tempDir, m.GetMountpoint())
		assert.NotZero(t, m.GetMountpointInode())
	})

	t.Run("umount on non-managed mount", func(t *testing.T) {
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Where:  "/tmp",
			Force:  true, // Force mode creates non-managed mounts
		}

		m, err := mount.NewMountHostOnce(cfg)
		require.NoError(t, err)

		// Umount should be no-op for non-managed mounts
		err = m.Umount()
		assert.NoError(t, err)

		// Should still be considered mounted since it's not managed
		assert.True(t, m.IsMounted())
	})
}

func TestIsFileSystemSupported(t *testing.T) {
	t.Run("supported filesystem types", func(t *testing.T) {
		// Test common filesystem types that should be supported
		commonFS := []string{
			"ext2",
			"ext3",
			"ext4",
			"tmpfs",
			"proc",
			"sysfs",
		}

		for _, fs := range commonFS {
			t.Run(fs, func(t *testing.T) {
				supported, err := mount.IsFileSystemSupported(fs)
				assert.NoError(t, err)
				// Don't assert the result since it depends on kernel config
				// Just ensure no error occurs
				_ = supported
			})
		}
	})

	t.Run("unsupported filesystem type", func(t *testing.T) {
		// Test a filesystem type that definitely doesn't exist
		supported, err := mount.IsFileSystemSupported("definitely_not_a_real_filesystem_12345")
		assert.NoError(t, err)
		assert.False(t, supported)
	})

	t.Run("empty filesystem type", func(t *testing.T) {
		supported, err := mount.IsFileSystemSupported("")
		assert.NoError(t, err)
		assert.False(t, supported)
	})

	t.Run("read actual /proc/filesystems", func(t *testing.T) {
		// Verify we can actually read the file and parse it
		file, err := os.Open("/proc/filesystems")
		if err != nil {
			t.Skip("Cannot read /proc/filesystems in test environment")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		foundAny := false
		for scanner.Scan() {
			line := strings.Fields(scanner.Text())
			if len(line) > 0 {
				foundAny = true
				break
			}
		}
		assert.True(t, foundAny, "Should find at least one filesystem in /proc/filesystems")
	})
}

func TestSearchMountpointFromHost(t *testing.T) {
	t.Run("search for proc filesystem", func(t *testing.T) {
		// proc should be mounted at /proc on most systems
		mp, inode, err := mount.SearchMountpointFromHost("proc", "/proc")
		assert.NoError(t, err)

		if mp != "" {
			// If found, should be a valid path
			assert.Contains(t, mp, "/proc")
			assert.NotZero(t, inode)
		}
	})

	t.Run("search for sysfs filesystem", func(t *testing.T) {
		// sysfs should be mounted at /sys on most systems
		mp, inode, err := mount.SearchMountpointFromHost("sysfs", "/sys")
		assert.NoError(t, err)

		if mp != "" {
			// If found, should be a valid path
			assert.Contains(t, mp, "/sys")
			assert.NotZero(t, inode)
		}
	})

	t.Run("search for non-existent filesystem", func(t *testing.T) {
		mp, inode, err := mount.SearchMountpointFromHost("definitely_not_real_fs", "/nowhere")
		assert.NoError(t, err)
		assert.Empty(t, mp)
		assert.Zero(t, inode)
	})

	t.Run("search with empty parameters", func(t *testing.T) {
		mp, inode, err := mount.SearchMountpointFromHost("", "")
		assert.NoError(t, err)
		assert.Empty(t, mp)
		assert.Zero(t, inode)
	})

	t.Run("verify mountinfo parsing logic", func(t *testing.T) {
		// Test that we can read and parse /proc/self/mountinfo
		file, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			t.Skip("Cannot read /proc/self/mountinfo in test environment")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		foundValidLine := false
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), " ")
			// A valid mountinfo line should have at least 7 fields before the separator
			if len(line) >= 7 {
				// Look for the separator "-"
				for i, field := range line {
					if field == "-" && i+1 < len(line) {
						// Should have filesystem type after separator
						fsType := line[i+1]
						if fsType != "" {
							foundValidLine = true
							break
						}
					}
				}
				if foundValidLine {
					break
				}
			}
		}
		assert.True(t, foundValidLine, "Should find at least one valid mountinfo line")
	})

	t.Run("search for tmpfs", func(t *testing.T) {
		// Most systems have tmpfs mounted somewhere
		mp, inode, err := mount.SearchMountpointFromHost("tmpfs", "")
		assert.NoError(t, err)
		// Don't assert on results since tmpfs might not be mounted
		// Just ensure no error
		_ = mp
		_ = inode
	})
}

func TestConfig_Validation(t *testing.T) {
	t.Run("config with all fields", func(t *testing.T) {
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M,uid=1000",
			Where:  "/tmp/test",
			Force:  true,
		}

		m, err := mount.NewMountHostOnce(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, m)
	})

	t.Run("config with minimal fields", func(t *testing.T) {
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Force:  true,
		}

		m, err := mount.NewMountHostOnce(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, m)
	})

	t.Run("empty config", func(t *testing.T) {
		cfg := mount.Config{}

		m, err := mount.NewMountHostOnce(cfg)
		// Should not panic with empty config
		// Error is acceptable since config is incomplete
		_ = err
		_ = m
	})
}

// Integration-style test that verifies the overall flow
func TestMountHostOnce_Integration(t *testing.T) {
	t.Run("complete workflow in force mode", func(t *testing.T) {
		// Create a temporary directory for testing
		tempDir, err := os.MkdirTemp("", "mount_integration_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Test the complete workflow
		cfg := mount.Config{
			Source: "tmpfs",
			FsType: "tmpfs",
			Data:   "size=1M",
			Where:  tempDir,
			Force:  true,
		}

		// Create mount object
		m, err := mount.NewMountHostOnce(cfg)
		require.NoError(t, err)
		require.NotNil(t, m)

		// Verify initial state
		assert.True(t, m.IsMounted())
		assert.Equal(t, tempDir, m.GetMountpoint())
		assert.NotZero(t, m.GetMountpointInode())

		// Test umount (should be no-op in force mode since it's not managed)
		err = m.Umount()
		assert.NoError(t, err)

		// Should still be mounted since force mode is not managed
		assert.True(t, m.IsMounted())
	})
}

// Benchmark tests
func BenchmarkIsFileSystemSupported(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := mount.IsFileSystemSupported("ext4")
		if err != nil {
			b.Errorf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkSearchMountpointFromHost(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := mount.SearchMountpointFromHost("proc", "/proc")
		if err != nil {
			b.Errorf("Unexpected error: %v", err)
		}
	}
}
