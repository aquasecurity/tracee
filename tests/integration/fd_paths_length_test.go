package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// Relative operations can create a path longer than PATH_MAX. This lets the
// test exercise the capture bound independently of the syscall's pathname bound.
func fdPathOfLength(t *testing.T, length int) (int, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "fdp-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dirfd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	require.NoError(t, err)
	path := root
	for length-len(path)-1 > 255 {
		name := strings.Repeat("d", 255)
		require.NoError(t, unix.Mkdirat(dirfd, name, 0700))
		next, err := unix.Openat(dirfd, name, unix.O_DIRECTORY|unix.O_RDONLY, 0)
		require.NoError(t, err)
		require.NoError(t, unix.Close(dirfd))
		dirfd = next
		path += "/" + name
	}
	name := strings.Repeat("f", length-len(path)-1)
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_RDWR, 0600)
	require.NoError(t, err)
	require.NoError(t, unix.Close(dirfd))
	return fd, path + "/" + name
}

func Test_FdPathsLongAndIncomplete(t *testing.T) {
	testutils.AssureIsRoot(t)
	_, output, _ := fdPathTracee(t, "close")
	truncatedBefore := fdPathCount("truncated")
	require.GreaterOrEqual(t, truncatedBefore, float64(0))
	expected := map[int32]string{}
	for i, size := range []int{63, 64, 255, 512, 3000, 4095, 4096} {
		fd, path := fdPathOfLength(t, size)
		high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 10000+i)
		require.NoError(t, err)
		require.NoError(t, unix.Close(fd))
		require.NoError(t, unix.Close(high))
		if size < 4096 {
			expected[int32(high)] = fmt.Sprintf("%d=%s", high, path)
		} else {
			expected[int32(high)] = ""
			t.Cleanup(func() {
				if !t.Failed() {
					return
				}
				for _, event := range fdPathEvents(output) {
					if event.Name != "close" {
						continue
					}
					for _, field := range event.Data {
						if field.Name != "fd" {
							continue
						}
						if field.GetInt32() >= 10000 || strings.HasPrefix(field.GetStr(), "1000") || strings.HasPrefix(field.GetStr(), "11000=") {
							t.Logf("fd value: numeric=%d string length=%d prefix=%.25s", field.GetInt32(), len(field.GetStr()), field.GetStr())
						}
					}
				}
				t.Logf("resolved=%v truncated=%v read_error=%v storage_error=%v", fdPathCount("resolved"), fdPathCount("truncated"), fdPathCount("read_error"), fdPathCount("storage_error"))
			})
		}
	}
	root, err := os.MkdirTemp("/tmp", "fdp-deep-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	path := filepath.Join(root, strings.Repeat("d/", 25), "file")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0600)
	require.NoError(t, err)
	high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 11000)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
	require.NoError(t, unix.Close(high))
	expected[int32(high)] = ""
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, event := range fdPathEvents(output) {
			if event.Name != "close" {
				continue
			}
			for _, field := range event.Data {
				if field.Name != "fd" {
					continue
				}
				if field.GetInt32() >= 10000 || strings.HasPrefix(field.GetStr(), "1000") || strings.HasPrefix(field.GetStr(), "11000=") {
					t.Logf("fd value: numeric=%d string length=%d prefix=%.25s", field.GetInt32(), len(field.GetStr()), field.GetStr())
				}
			}
		}
		t.Logf("resolved=%v truncated=%v read_error=%v storage_error=%v", fdPathCount("resolved"), fdPathCount("truncated"), fdPathCount("read_error"), fdPathCount("storage_error"))
	})

	require.Eventually(t, func() bool {
		seen := map[int32]bool{}
		for _, event := range fdPathEvents(output) {
			if event.Name != "close" {
				continue
			}
			for _, field := range event.Data {
				if field.Name != "fd" {
					continue
				}
				if value, ok := field.Value.(*pb.EventValue_Int32); ok {
					if want, exists := expected[value.Int32]; exists && want == "" {
						seen[value.Int32] = true
					}
				} else {
					for fd, want := range expected {
						if want != "" && field.GetStr() == want {
							seen[fd] = true
						}
					}
				}
			}
		}
		return len(seen) == len(expected)
	}, 10*time.Second, 100*time.Millisecond, "paths must be complete, or stay numeric when capture is bounded")
	require.Eventually(t, func() bool { return fdPathCount("truncated") >= truncatedBefore+2 }, time.Second, 100*time.Millisecond)
}
