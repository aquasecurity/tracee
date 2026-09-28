package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Open the map owned by this Tracee process, not another Tracee on the host.
func fdPathMap(t *testing.T, pid int) *bpf.BPFMapLow {
	t.Helper()
	directory := fmt.Sprintf("/proc/%d/fdinfo", pid)
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	for _, entry := range entries {
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		} // The process may close unrelated descriptors.
		for _, line := range strings.Split(string(contents), "\n") {
			value, ok := strings.CutPrefix(line, "map_id:")
			if !ok {
				continue
			}
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			require.NoError(t, err)
			candidate, err := bpf.GetMapByID(uint32(id))
			require.NoError(t, err)
			if candidate.Name() == "fd_arg_path_map" {
				t.Cleanup(func() { _ = unix.Close(candidate.FileDescriptor()) })
				return candidate
			}
			require.NoError(t, unix.Close(candidate.FileDescriptor()))
		}
	}
	t.Fatal("Tracee's FD path map was not found")
	return nil
}

// This test is also a subprocess helper. A successful exec must replace only
// that subprocess, not the integration runner.
func Test_FdPathsExecHelper(t *testing.T) {
	if os.Getenv("TRACEE_FD_EXEC_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	runtime.LockOSThread()
	go func() {
		runtime.LockOSThread()
		// If this goroutine is on the leader, hold that thread while another
		// goroutine starts. The selected thread must have TID != PID.
		if unix.Gettid() == os.Getpid() {
			go fdPathExecFromThread()
			select {}
		}
		fdPathExecFromThread()
	}()
	select {}
}

func fdPathExecFromThread() {
	runtime.LockOSThread()
	name, _ := unix.BytePtrFromString("fdexec-check")
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(name)), 0, 0, 0); err != nil {
		os.Exit(2)
	}
	fd, err := unix.Open("/usr/bin/true", unix.O_RDONLY, 0)
	if err != nil {
		os.Exit(3)
	}
	fmt.Printf("pid=%d tid=%d\n", os.Getpid(), unix.Gettid())
	empty := []byte{0}
	arg0, _ := unix.BytePtrFromString("true")
	argv := []*byte{arg0, nil}
	envp := []*byte{nil}
	_, _, errno := unix.RawSyscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])), unix.AT_EMPTY_PATH, 0)
	fmt.Printf("execveat failed: %v\n", errno)
	os.Exit(4)
}

func Test_FdPathsExecThreadCleanup(t *testing.T) {
	testutils.AssureIsRoot(t)
	tracer, output, _ := fdPathTraceeOptions(t, "execveat", "comm=fdexec-check", true)
	snapshots := fdPathMap(t, tracer.Process.Pid)
	binary, err := os.Executable()
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		child := exec.CommandContext(ctx, binary, "-test.run=^Test_FdPathsExecHelper$")
		child.Env = append(os.Environ(), "TRACEE_FD_EXEC_HELPER=1")
		result, err := child.CombinedOutput()
		cancel()
		require.NoError(t, err, string(result))
		var pid, tid int
		_, err = fmt.Sscanf(string(result), "pid=%d tid=%d", &pid, &tid)
		require.NoError(t, err)
		require.NotEqual(t, pid, tid)
	}
	require.Eventually(t, func() bool {
		count := 0
		for _, event := range fdPathEvents(output) {
			if event.Name != "execveat" {
				continue
			}
			for _, field := range event.Data {
				if field.Name == "dirfd" && strings.HasSuffix(field.GetStr(), "=/usr/bin/true") {
					count++
				}
			}
		}
		return count == 5
	}, 10*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		var key uint32
		return errors.Is(snapshots.GetNextKey(nil, unsafe.Pointer(&key)), unix.ENOENT)
	}, time.Second, 100*time.Millisecond, "successful exec from a non-leader left an FD path snapshot behind")
}
