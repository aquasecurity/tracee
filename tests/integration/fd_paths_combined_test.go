package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Exercise the original clock/key problems and the follow-ups in the same
// pipeline: concurrent FD reuse, a backlog exceeding the old LRU, long paths,
// invalid descriptors, varied argument names/types, sorting, and decoded data.
func Test_FdPathsCombinedRegression(t *testing.T) {
	testutils.AssureIsRoot(t)
	const workers, calls = 8, 160
	descriptors := make([]int, workers)
	paths := make([]string, workers)
	for i := range descriptors {
		descriptors[i], paths[i] = fdPathOfLength(t, 128+i*64)
		fd := descriptors[i]
		t.Cleanup(func() { _ = unix.Close(fd) })
	}
	root, err := os.MkdirTemp("/tmp", "fd-combined-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dirfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(dirfd) })
	file, err := os.Create(filepath.Join(root, "file"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	require.NoError(t, file.Truncate(4096))
	invalidName, err := os.Create(filepath.Join(root, "a\xffb"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = invalidName.Close() })
	started := time.Now().Unix()
	tracer, output, logPath := fdPathTraceeOptions(t,
		"close,dup,getpid,openat,getdents64,symlinkat,mmap,fsconfig",
		fmt.Sprintf("pid=%d", os.Getpid()), true,
		"--output", "sort-events", "--enrichment", "decoded-data")

	type workerResult struct {
		tid   int
		index int
	}
	ready := make(chan workerResult, workers)
	done := make(chan error, workers)
	start := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	for i, original := range descriptors {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- workerResult{tid: unix.Gettid(), index: i}
			<-start
			var workErr error
			for n := 0; n < calls; n++ {
				duplicate, err := unix.Dup(original)
				if err != nil {
					workErr = err
					break
				}
				if err := unix.Close(duplicate); err != nil {
					workErr = err
					break
				}
				if n%32 == 0 {
					if err := unix.Close(-1); err != unix.EBADF {
						workErr = fmt.Errorf("invalid close returned %v", err)
						break
					}
					_, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
					if errno != 0 {
						workErr = errno
						break
					}
				}
			}
			done <- workErr
			<-release // Keep this TID out of the test runner's subsequent I/O.
		}()
	}
	owners := map[uint32]int{}
	for i := 0; i < workers; i++ {
		worker := <-ready
		owners[uint32(worker.tid)] = worker.index
	}
	require.NoError(t, tracer.Process.Signal(syscall.SIGSTOP))
	require.Eventually(t, func() bool {
		contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tracer.Process.Pid))
		return err == nil && strings.Contains(string(contents), "State:\tT")
	}, time.Second, 10*time.Millisecond)
	close(start)
	for i := 0; i < workers; i++ {
		require.NoError(t, <-done)
	}

	opened, err := unix.Openat(dirfd, "file", unix.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(opened))
	_, err = unix.Getdents(dirfd, make([]byte, 4096))
	require.NoError(t, err)
	require.NoError(t, unix.Symlinkat("file", dirfd, "link"))
	mapped, err := unix.Mmap(int(file.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	require.NoError(t, err)
	require.NoError(t, unix.Munmap(mapped))
	_, _, errno := unix.Syscall6(unix.SYS_FSCONFIG, file.Fd(), unix.FSCONFIG_CMD_CREATE, 0, 0, 0, 0)
	require.NotZero(t, errno)
	invalidCopy, err := unix.Dup(int(invalidName.Fd()))
	require.NoError(t, err)
	require.NoError(t, unix.Close(invalidCopy))
	require.NoError(t, tracer.Process.Signal(syscall.SIGCONT))

	expected := map[string]string{
		"dup:oldfd":          fmt.Sprintf("%d=%s", invalidName.Fd(), filepath.Join(root, "ab")),
		"openat:dirfd":       fmt.Sprintf("%d=%s", dirfd, root),
		"getdents64:fd":      fmt.Sprintf("%d=%s", dirfd, root),
		"symlinkat:newdirfd": fmt.Sprintf("%d=%s", dirfd, root),
		"mmap:fd":            fmt.Sprintf("%d=%s", file.Fd(), file.Name()),
		"fsconfig:fs_fd":     fmt.Sprintf("%d=%s", file.Fd(), file.Name()),
	}
	var diagnostic string
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(diagnostic)
		}
	})
	require.Eventually(t, func() bool {
		counts := map[string]int{}
		seen := map[string]bool{}
		wrong := 0
		records := fdPathEvents(output)
		// The runtime may have used these threads for setup I/O before they
		// were locked by our workers. Bound each workload by its first dup.
		first := map[uint32]int64{}
		for _, event := range records {
			tid := event.GetWorkload().GetProcess().GetThread().GetHostTid().GetValue()
			index, worker := owners[tid]
			if !worker || event.Name != "dup" {
				continue
			}
			for _, field := range event.Data {
				if field.Name == "oldfd" && field.GetStr() == fmt.Sprintf("%d=%s", descriptors[index], paths[index]) {
					ts := event.GetTimestamp().AsTime().UnixNano()
					if previous, ok := first[tid]; !ok || ts < previous {
						first[tid] = ts
					}
				}
			}
		}
		for _, event := range records {
			tid := event.GetWorkload().GetProcess().GetThread().GetHostTid().GetValue()
			index, worker := owners[tid]
			begin, inWorkload := first[tid]
			if worker && inWorkload && event.GetTimestamp().AsTime().UnixNano() >= begin {
				if event.GetTimestamp().GetSeconds() < started || event.GetTimestamp().GetSeconds() > time.Now().Unix()+1 {
					wrong++
				}
				for _, field := range event.Data {
					switch {
					case event.Name == "dup" && field.Name == "oldfd":
						counts["dup"]++
						if field.GetStr() != fmt.Sprintf("%d=%s", descriptors[index], paths[index]) {
							wrong++
						}
					case event.Name == "close" && field.Name == "fd":
						if field.GetInt32() == -1 {
							counts["invalid"]++
						} else {
							counts["close"]++
							if !strings.HasSuffix(field.GetStr(), "="+paths[index]) {
								wrong++
							}
						}
					case event.Name == "getpid" && field.Name == "returnValue":
						counts["getpid"]++
						if field.GetInt64() != int64(os.Getpid()) {
							wrong++
						}
					}
				}
			}
			for _, field := range event.Data {
				key := event.Name + ":" + field.Name
				if want, ok := expected[key]; ok && field.GetStr() == want {
					seen[key] = true
				}
			}
		}
		diagnostic = fmt.Sprintf("counts=%v selected=%v wrong=%d", counts, seen, wrong)
		return wrong == 0 && len(seen) == len(expected) && counts["dup"] == workers*calls &&
			counts["close"] == workers*calls && counts["invalid"] == workers*calls/32 && counts["getpid"] == workers*calls/32
	}, 15*time.Second, 100*time.Millisecond, "combined FD-path regression")
	require.GreaterOrEqual(t, fdPathCount("unavailable"), float64(workers*calls/32))
	require.Zero(t, fdPathCount("read_error"))
	require.Zero(t, fdPathCount("storage_error"))
	contents, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotContains(t, string(contents), "operation not permitted")
	require.NotContains(t, string(contents), "FD path")
}

func Test_FdPathsNumericFilterAndDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			testutils.AssureIsRoot(t)
			file, err := os.CreateTemp("/tmp", "fd-filter-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = file.Close(); _ = os.Remove(file.Name()) })
			selected, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 256)
			require.NoError(t, err)
			rejected, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 256)
			require.NoError(t, err)
			_, output, _ := fdPathTraceeOptions(t, fmt.Sprintf("close.data.fd=%d", selected),
				fmt.Sprintf("pid=%d", os.Getpid()), enabled)
			require.NoError(t, unix.Close(rejected))
			require.NoError(t, unix.Close(selected))
			require.Eventually(t, func() bool {
				events := fdPathEvents(output)
				if len(events) != 1 || events[0].Name != "close" {
					return false
				}
				for _, field := range events[0].Data {
					if field.Name == "fd" {
						if enabled {
							return field.GetStr() == fmt.Sprintf("%d=%s", selected, file.Name())
						}
						return field.GetInt32() == int32(selected)
					}
				}
				return false
			}, 10*time.Second, 100*time.Millisecond)
			if !enabled {
				require.Zero(t, fdPathCount("resolved"))
			}
		})
	}
}
