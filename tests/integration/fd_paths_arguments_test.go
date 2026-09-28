package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/tests/testutils"
)

func Test_FdPathsSelectedArguments(t *testing.T) {
	testutils.AssureIsRoot(t)
	root, err := os.MkdirTemp("/tmp", "fdp-args-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	file, err := os.Create(filepath.Join(root, "file"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	require.NoError(t, file.Truncate(4096))
	dir, err := os.Open(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dir.Close() })
	sockfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sockfd) })
	_, output, _ := fdPathTracee(t, "dup,getdents64,openat,symlinkat,mmap,fsconfig,getsockname,execveat,socket_dup")

	duplicated, err := syscall.Dup(int(file.Fd()))
	require.NoError(t, err)
	require.NoError(t, syscall.Close(duplicated))
	_, err = unix.Getdents(int(dir.Fd()), make([]byte, 4096))
	require.NoError(t, err)
	opened, err := unix.Openat(int(dir.Fd()), "file", unix.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(opened))
	require.NoError(t, unix.Symlinkat("file", int(dir.Fd()), "link"))
	mapped, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	require.NoError(t, err)
	require.NoError(t, unix.Munmap(mapped))
	// fsconfig's event definition currently decodes fs_fd as a pointer. Even
	// when the syscall rejects an ordinary file, its entry FD has a valid path.
	_, _, errno := unix.Syscall6(unix.SYS_FSCONFIG, file.Fd(), unix.FSCONFIG_CMD_CREATE, 0, 0, 0, 0)
	require.NotZero(t, errno)
	sockCopy, err := unix.Dup(sockfd)
	require.NoError(t, err)
	require.NoError(t, unix.Close(sockCopy))
	_, err = unix.Getsockname(sockfd)
	require.NoError(t, err)
	missing, err := unix.BytePtrFromString("missing-executable")
	require.NoError(t, err)
	_, _, errno = unix.Syscall6(unix.SYS_EXECVEAT, dir.Fd(), uintptr(unsafe.Pointer(missing)), 0, 0, 0, 0)
	require.Equal(t, unix.ENOENT, errno)

	expected := map[string]string{
		"dup:oldfd":          fmt.Sprintf("%d=%s", file.Fd(), file.Name()),
		"getdents64:fd":      fmt.Sprintf("%d=%s", dir.Fd(), root),
		"openat:dirfd":       fmt.Sprintf("%d=%s", dir.Fd(), root),
		"symlinkat:newdirfd": fmt.Sprintf("%d=%s", dir.Fd(), root),
		"mmap:fd":            fmt.Sprintf("%d=%s", file.Fd(), file.Name()),
		"fsconfig:fs_fd":     fmt.Sprintf("%d=%s", file.Fd(), file.Name()),
		"execveat:dirfd":     fmt.Sprintf("%d=%s", dir.Fd(), root),
	}
	var lastState string
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(lastState)
		}
	})
	require.Eventually(t, func() bool {
		samples := map[string]string{}
		seen := map[string]bool{}
		socket := false
		socketDup := false
		mmapReturn := false
		execFailed := false
		for _, event := range fdPathEvents(output) {
			selected := false
			for _, field := range event.Data {
				key := event.Name + ":" + field.Name
				if key == "socket_dup:oldfd" && field.GetInt32() == int32(sockfd) {
					socketDup = true
				}
				if _, ok := expected[key]; ok || key == "getsockname:sockfd" {
					samples[key] = field.String()
				}
				if want, ok := expected[key]; ok && field.GetStr() == want {
					seen[key] = true
					selected = true
				}
				if key == "getsockname:sockfd" && strings.HasPrefix(field.GetStr(), fmt.Sprintf("%d=", sockfd)) {
					socket = true
				}
			}
			if selected {
				for _, field := range event.Data {
					if event.Name == "mmap" && field.Name == "returnValue" && len(event.Data) == 7 {
						mmapReturn = true
					}
					if event.Name == "execveat" && field.Name == "returnValue" && field.GetInt64() == -int64(unix.ENOENT) {
						execFailed = true
					}
				}
			}
		}
		lastState = fmt.Sprintf("seen=%v socket=%v socketDup=%v mmapReturn=%v execFailed=%v samples=%v", seen, socket, socketDup, mmapReturn, execFailed, samples)
		return len(seen) == len(expected) && socket && socketDup && mmapReturn && execFailed
	}, 10*time.Second, 100*time.Millisecond, "selected argument names, types, positions and return values must survive enrichment")
}
