package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/tests/testutils"
)

func Test_FdPathsSurviveCPUMigration(t *testing.T) {
	testutils.AssureIsRoot(t)
	var allowed unix.CPUSet
	require.NoError(t, unix.SchedGetaffinity(0, &allowed))
	var cpus []int
	for cpu := 0; cpu < 1024; cpu++ {
		if allowed.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) < 2 {
		t.Skip("requires two allowed CPUs")
	}
	root, err := os.MkdirTemp("/tmp", "fd-migration-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	path := filepath.Join(root, "pipe")
	require.NoError(t, unix.Mkfifo(path, 0600))
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	tracer, output, _ := fdPathTracee(t, "read")
	snapshots := fdPathMap(t, tracer.Process.Pid)
	ready := make(chan int, 1)
	done := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		_, _ = unix.Write(fd, []byte{1})
		select {
		case <-finished:
		case <-time.After(time.Second):
		}
	})
	go func() {
		defer close(finished)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() { _ = unix.SchedSetaffinity(0, &allowed) }()
		var first unix.CPUSet
		first.Set(cpus[0])
		if err := unix.SchedSetaffinity(0, &first); err != nil {
			ready <- 0
			done <- err
			return
		}
		ready <- unix.Gettid()
		_, err := unix.Read(fd, make([]byte, 1))
		done <- err
	}()
	tid := <-ready
	require.NotZero(t, tid)
	key := uint32(tid)
	// Wait until the read has captured its path and is blocked in the kernel.
	require.Eventually(t, func() bool {
		_, err := snapshots.GetValue(unsafe.Pointer(&key))
		return err == nil
	}, time.Second, 10*time.Millisecond)
	// The event must retain the entry-time name even if the file is renamed
	// while the read is blocked. A later procfs lookup would see the new name.
	require.NoError(t, unix.Rename(path, path+"-renamed"))
	var second unix.CPUSet
	second.Set(cpus[1])
	require.NoError(t, unix.SchedSetaffinity(tid, &second))
	// The read must return on the other CPU; its snapshot belongs to the TID.
	_, err = unix.Write(fd, []byte{1})
	require.NoError(t, err)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked read did not finish")
	}
	require.Eventually(t, func() bool {
		for _, event := range fdPathEvents(output) {
			if event.Name != "read" || event.GetWorkload().GetProcess().GetThread().GetHostTid().GetValue() != uint32(tid) {
				continue
			}
			for _, field := range event.Data {
				if field.Name == "fd" && field.GetStr() == fmt.Sprintf("%d=%s", fd, path) {
					return true
				}
			}
		}
		return false
	}, 10*time.Second, 100*time.Millisecond)
}
