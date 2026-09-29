package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/libbpfgo"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

const fdPathWait = 10 * time.Second

// fdPathSnapshotBudget is the memory the snapshot map may cost per entry: the
// value, without the kernel's bookkeeping. It is a literal on purpose. Raising
// MAX_FD_PATH_SIZE multiplies the preallocated memory of every Tracee that
// enables fd-paths, so that change has to edit this number as well.
const fdPathSnapshotBudget = 272

// fdPathInstance is a Tracee loaded into the test process, scoped to the
// workload threads of the helper subprocess.
type fdPathInstance struct {
	tracee    *tracee.Tracee
	events    *testutils.EventBuffer
	snapshots *bpf.BPFMapLow
}

func fdPathStart(t *testing.T, output config.OutputConfig, rules ...k8s.Rule) *fdPathInstance {
	t.Helper()
	policies := testutils.NewPolicies([]testutils.PolicyFileWithID{{
		Id: 1,
		PolicyFile: v1beta1.PolicyFile{
			Metadata: v1beta1.Metadata{Name: "fd-paths"},
			Spec: k8s.PolicySpec{
				Scope:          []string{"comm=" + fdPathHelperComm},
				DefaultActions: []string{"log"},
				Rules:          rules,
			},
		},
	}})
	cfg := config.Config{Capabilities: &config.CapabilitiesConfig{BypassCaps: true}}
	for _, p := range policies {
		cfg.InitialPolicies = append(cfg.InitialPolicies, p)
	}

	ctx, cancel := context.WithCancel(context.Background())
	trc, err := testutils.StartTracee(ctx, t, cfg, &output, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := testutils.WaitForTraceeStop(trc); err != nil {
			t.Log(err)
		}
	})
	require.NoError(t, testutils.WaitForTraceeStart(trc))

	stream, err := trc.Subscribe(config.Stream{})
	require.NoError(t, err)
	t.Cleanup(func() { trc.Unsubscribe(stream) })
	instance := &fdPathInstance{tracee: trc, events: testutils.NewEventBuffer(), snapshots: fdPathSnapshotMap(t)}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-stream.ReceiveEvents():
				if event != nil {
					instance.events.AddEvent(event)
				}
			}
		}
	}()
	return instance
}

func fdPathRules(names ...string) []k8s.Rule {
	rules := make([]k8s.Rule, 0, len(names))
	for _, name := range names {
		rules = append(rules, k8s.Rule{Event: name, Filters: []string{}})
	}
	return rules
}

// fdPathSnapshotMap opens the map of the Tracee in this process, not the map
// of another Tracee on the host.
func fdPathSnapshotMap(t *testing.T) *bpf.BPFMapLow {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fdinfo")
	require.NoError(t, err)
	for _, entry := range entries {
		contents, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", entry.Name()))
		if err != nil {
			continue // closed since the directory was read
		}
		for _, line := range strings.Split(string(contents), "\n") {
			value, ok := strings.CutPrefix(line, "map_id:")
			if !ok {
				continue
			}
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			require.NoError(t, err)
			candidate, err := bpf.GetMapByID(uint32(id))
			if err != nil {
				continue
			}
			if candidate.Name() == "fd_arg_path_map" {
				t.Cleanup(func() { _ = unix.Close(candidate.FileDescriptor()) })
				return candidate
			}
			_ = unix.Close(candidate.FileDescriptor())
		}
	}
	t.Fatal("fd_arg_path_map was not found")
	return nil
}

func (i *fdPathInstance) snapshotCount(t *testing.T) int {
	t.Helper()
	count := 0
	var key, next uint32
	err := i.snapshots.GetNextKey(nil, unsafe.Pointer(&next))
	for err == nil {
		count++
		key = next
		err = i.snapshots.GetNextKey(unsafe.Pointer(&key), unsafe.Pointer(&next))
	}
	require.ErrorIs(t, err, unix.ENOENT)
	return count
}

func (i *fdPathInstance) hasSnapshot(tid int) bool {
	key := uint32(tid)
	_, err := i.snapshots.GetValue(unsafe.Pointer(&key))
	return err == nil
}

// fdPathCounts is a copy of the capture counters, to assert on differences.
type fdPathCounts struct {
	resolved, unavailable, readError, storageError, truncated uint64
}

func fdPathCountsOf(stats *metrics.Stats) fdPathCounts {
	return fdPathCounts{
		resolved:     stats.FDPaths.Resolved.Get(),
		unavailable:  stats.FDPaths.Unavailable.Get(),
		readError:    stats.FDPaths.ReadError.Get(),
		storageError: stats.FDPaths.StorageError.Get(),
		truncated:    stats.FDPaths.Truncated.Get(),
	}
}

// fdPathOutput collects what the helper prints besides its reports. The
// stderr copier of os/exec and the stdout reader write to it concurrently.
type fdPathOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (o *fdPathOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.Write(p)
}

func (o *fdPathOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.String()
}

// fdPathWorkload is a running helper subprocess.
type fdPathWorkload struct {
	cmd     *exec.Cmd
	root    string
	reports chan fdPathReport
	done    chan error
	output  *fdPathOutput
}

func fdPathRun(t *testing.T, name string) *fdPathWorkload {
	t.Helper()
	// Not t.TempDir(): its name contains the test name, and the workloads
	// compute path lengths from this prefix.
	root, err := os.MkdirTemp("/tmp", "fdp-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	binary, err := os.Executable()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	w := &fdPathWorkload{
		cmd:     exec.CommandContext(ctx, binary, "-test.run=^Test_FdPathsHelper$"),
		root:    root,
		reports: make(chan fdPathReport, 16),
		done:    make(chan error, 1),
		output:  &fdPathOutput{},
	}
	w.cmd.Env = append(os.Environ(), fdPathHelperEnv+"="+name, fdPathHelperRootEnv+"="+root)
	stdout, err := w.cmd.StdoutPipe()
	require.NoError(t, err)
	w.cmd.Stderr = w.output
	require.NoError(t, w.cmd.Start())
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line, ok := strings.CutPrefix(scanner.Text(), fdPathReportPrefix)
			if !ok {
				fmt.Fprintln(w.output, scanner.Text())
				continue
			}
			var report fdPathReport
			if err := json.Unmarshal([]byte(line), &report); err == nil {
				w.reports <- report
			}
		}
		close(w.reports)
		w.done <- w.cmd.Wait()
	}()
	return w
}

func (w *fdPathWorkload) report(t *testing.T) fdPathReport {
	t.Helper()
	select {
	case report, ok := <-w.reports:
		require.True(t, ok, "workload ended without a report: %s", w.output)
		return report
	case <-time.After(fdPathWait):
		t.Fatalf("no report from the workload: %s", w.output)
		return fdPathReport{}
	}
}

func (w *fdPathWorkload) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-w.done:
		require.NoError(t, err, w.output.String())
	case <-time.After(fdPathWait):
		t.Fatalf("workload did not end: %s", w.output)
	}
}

// fdPathField returns how an event reports a descriptor: as a path once it is
// enriched, as its numeric value otherwise.
func fdPathField(event *pb.Event, name string) (enriched string, numeric int64, found bool) {
	for _, field := range event.Data {
		if field.Name != name {
			continue
		}
		switch value := field.Value.(type) {
		case *pb.EventValue_Str:
			return value.Str, 0, true
		case *pb.EventValue_Int32:
			return "", int64(value.Int32), true
		case *pb.EventValue_Int64:
			return "", value.Int64, true
		case *pb.EventValue_UInt32:
			return "", int64(value.UInt32), true
		case *pb.EventValue_Pointer:
			return "", int64(value.Pointer), true
		}
	}
	return "", 0, false
}

func fdPathEventsOf(buffer *testutils.EventBuffer, tid int, name string) []*pb.Event {
	var selected []*pb.Event
	for _, event := range buffer.GetCopy() {
		if event.Name == name && event.GetWorkload().GetProcess().GetThread().GetHostTid().GetValue() == uint32(tid) {
			selected = append(selected, event)
		}
	}
	return selected
}

// fdPathExpect waits for an event of the thread whose field reports the case.
func fdPathExpect(t *testing.T, instance *fdPathInstance, tid int, event, field string, c fdPathCase) {
	t.Helper()
	var seen []string
	matched := assert.Eventually(t, func() bool {
		seen = seen[:0]
		for _, e := range fdPathEventsOf(instance.events, tid, event) {
			enriched, numeric, found := fdPathField(e, field)
			if !found {
				continue
			}
			seen = append(seen, fmt.Sprintf("%q/%d", enriched, numeric))
			if c.Path == "" && enriched == "" && numeric == int64(int32(c.FD)) {
				return true
			}
			if c.Path != "" && enriched == fmt.Sprintf("%d=%s", c.FD, c.Path) {
				return true
			}
		}
		return false
	}, fdPathWait, 50*time.Millisecond)
	if !matched {
		t.Errorf("%s: no %s event with %s for fd %d and path %q (%d bytes); got %v",
			c.Name, event, field, c.FD, c.Path, len(c.Path), seen)
	}
}

// fdPathParked reports whether a thread is inside the given syscall.
func fdPathParked(pid, tid int, syscall int) bool {
	contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/syscall", pid, tid))
	if err != nil {
		return false
	}
	number, _, _ := strings.Cut(string(contents), " ")
	return number == strconv.Itoa(syscall)
}

func fdPathRelease(t *testing.T, path string) {
	t.Helper()
	fifo, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	defer func() { _ = unix.Close(fifo) }()
	_, err = unix.Write(fifo, []byte{1})
	require.NoError(t, err)
}

func Test_FdPaths(t *testing.T) {
	testutils.AssureIsRoot(t)

	instance := fdPathStart(t, config.OutputConfig{FdPaths: true, DecodedData: true},
		fdPathRules("close", "dup", "read", "getdents64", "openat", "symlinkat", "mmap", "fsconfig",
			"getsockname", "execveat")...)

	t.Run("memory budget", func(t *testing.T) {
		assert.Equal(t, bpf.MapTypeHash, instance.snapshots.Type())
		assert.Equal(t, uint32(1024), instance.snapshots.MaxEntries())
		assert.LessOrEqual(t, instance.snapshots.ValueSize(), fdPathSnapshotBudget)
	})

	t.Run("path bounds and invalid descriptors", func(t *testing.T) {
		before := fdPathCountsOf(instance.tracee.Stats())
		workload := fdPathRun(t, "paths")
		report := workload.report(t)
		workload.wait(t)
		for _, c := range report.Cases {
			fdPathExpect(t, instance, report.TID, "close", "fd", c)
		}
		after := fdPathCountsOf(instance.tracee.Stats())
		assert.GreaterOrEqual(t, after.resolved-before.resolved, uint64(4), "lengths 63, 64, 255 and the UTF-8 name")
		assert.GreaterOrEqual(t, after.truncated-before.truncated, uint64(3), "lengths 256, 1000 and the deep path")
		assert.GreaterOrEqual(t, after.unavailable-before.unavailable, uint64(3), "three invalid descriptors")
		assert.Zero(t, after.readError-before.readError)
		assert.Zero(t, after.storageError-before.storageError)
	})

	t.Run("selected arguments", func(t *testing.T) {
		workload := fdPathRun(t, "arguments")
		report := workload.report(t)
		workload.wait(t)
		for _, c := range report.Cases {
			event, field, _ := strings.Cut(c.Name, ":")
			if c.Path != "" {
				fdPathExpect(t, instance, report.TID, event, field, c)
				continue
			}
			// A socket has no path in a filesystem; only its descriptor is known.
			assert.Eventually(t, func() bool {
				for _, e := range fdPathEventsOf(instance.events, report.TID, event) {
					if enriched, _, _ := fdPathField(e, field); strings.HasPrefix(enriched, fmt.Sprintf("%d=", c.FD)) {
						return true
					}
				}
				return false
			}, fdPathWait, 50*time.Millisecond, c.Name)
		}
		// The header must not take an argument slot or move the return value.
		for _, e := range fdPathEventsOf(instance.events, report.TID, "mmap") {
			if enriched, _, _ := fdPathField(e, "fd"); enriched != "" {
				assert.Len(t, e.Data, 7, "six arguments and the return value")
			}
		}
		failed := false
		for _, e := range fdPathEventsOf(instance.events, report.TID, "execveat") {
			if _, value, found := fdPathField(e, "returnValue"); found && value == -int64(unix.ENOENT) {
				failed = true
			}
		}
		assert.True(t, failed, "failed execveat keeps its return value")
	})

	t.Run("blocked syscall keeps its entry path", func(t *testing.T) {
		var allowed unix.CPUSet
		require.NoError(t, unix.SchedGetaffinity(0, &allowed))
		workload := fdPathRun(t, "blocked")
		report := workload.report(t)
		c := report.Cases[0]
		require.Eventually(t, func() bool {
			return fdPathParked(report.PID, report.TID, unix.SYS_READ) && instance.hasSnapshot(report.TID)
		}, fdPathWait, 10*time.Millisecond, "read is parked with a snapshot")

		// A lookup after the syscall returns would see the new name and,
		// with per-CPU state, the wrong CPU.
		require.NoError(t, unix.Rename(c.Path, c.Path+"-renamed"))
		if allowed.Count() > 1 {
			for cpu := 0; cpu < 1024; cpu++ {
				if allowed.IsSet(cpu) {
					var other unix.CPUSet
					other.Set(cpu)
					_ = unix.SchedSetaffinity(report.TID, &other)
				}
			}
		}
		fdPathRelease(t, c.Path+"-renamed")
		workload.wait(t)

		fdPathExpect(t, instance, report.TID, "read", "fd", c)
		assert.False(t, instance.hasSnapshot(report.TID), "snapshot outlived its syscall")
	})

	t.Run("exec from a thread releases the snapshot", func(t *testing.T) {
		workload := fdPathRun(t, "exec")
		report := workload.report(t)
		workload.wait(t)
		require.NotEqual(t, report.PID, report.TID)
		fdPathExpect(t, instance, report.TID, "execveat", "dirfd", report.Cases[0])
		assert.False(t, instance.hasSnapshot(report.TID), "snapshot outlived its thread")
	})

	t.Run("concurrent threads", func(t *testing.T) {
		const threads, calls = 8, 160
		before := fdPathCountsOf(instance.tracee.Stats())
		workload := fdPathRun(t, "concurrent")
		reports := make([]fdPathReport, 0, threads)
		for len(reports) < threads {
			reports = append(reports, workload.report(t))
		}
		workload.wait(t)
		var diagnostic string
		ok := assert.Eventually(t, func() bool {
			diagnostic = ""
			for _, report := range reports {
				want := report.Cases[0]
				dups, closes, wrong := 0, 0, 0
				for _, e := range fdPathEventsOf(instance.events, report.TID, "dup") {
					dups++
					if enriched, _, _ := fdPathField(e, "oldfd"); enriched != fmt.Sprintf("%d=%s", want.FD, want.Path) {
						wrong++
					}
				}
				for _, e := range fdPathEventsOf(instance.events, report.TID, "close") {
					closes++
					if enriched, _, _ := fdPathField(e, "fd"); !strings.HasSuffix(enriched, "="+want.Path) {
						wrong++
					}
				}
				if dups != calls || closes != calls || wrong != 0 {
					diagnostic += fmt.Sprintf("tid %d: dup=%d close=%d wrong=%d; ", report.TID, dups, closes, wrong)
				}
			}
			return diagnostic == ""
		}, fdPathWait, 100*time.Millisecond)
		if !ok {
			t.Error(diagnostic)
		}
		after := fdPathCountsOf(instance.tracee.Stats())
		assert.Zero(t, after.storageError-before.storageError)
	})

	t.Run("no snapshot is left behind", func(t *testing.T) {
		assert.Eventually(t, func() bool { return instance.snapshotCount(t) == 0 },
			fdPathWait, 50*time.Millisecond)
	})
}

// A full map must cost the path, never the event or another thread's path.
func Test_FdPathsCapacity(t *testing.T) {
	testutils.AssureIsRoot(t)
	const threads, capacity = 4, 2

	instance := fdPathStart(t, config.OutputConfig{FdPaths: true, FdPathsMaxEntries: capacity},
		fdPathRules("read")...)
	require.Equal(t, uint32(capacity), instance.snapshots.MaxEntries())

	before := fdPathCountsOf(instance.tracee.Stats())
	workload := fdPathRun(t, "capacity")
	reports := make([]fdPathReport, 0, threads)
	for len(reports) < threads {
		reports = append(reports, workload.report(t))
	}
	require.Eventually(t, func() bool {
		for _, report := range reports {
			if !fdPathParked(report.PID, report.TID, unix.SYS_READ) {
				return false
			}
		}
		return true
	}, fdPathWait, 10*time.Millisecond, "reads are parked")
	assert.Equal(t, capacity, instance.snapshotCount(t))

	for _, report := range reports {
		fdPathRelease(t, report.Cases[0].Path)
	}
	workload.wait(t)

	enriched := 0
	for _, report := range reports {
		c := report.Cases[0]
		if !instance.hasSnapshotRecorded(t, report.TID, c) {
			c.Path = "" // no slot was free: the descriptor stays numeric
		} else {
			enriched++
		}
		fdPathExpect(t, instance, report.TID, "read", "fd", c)
	}
	assert.Equal(t, capacity, enriched)
	after := fdPathCountsOf(instance.tracee.Stats())
	assert.Equal(t, uint64(threads-capacity), after.storageError-before.storageError)
	assert.Eventually(t, func() bool { return instance.snapshotCount(t) == 0 }, fdPathWait, 50*time.Millisecond)
}

// hasSnapshotRecorded waits for the thread's read event and reports whether
// it carries the path.
func (i *fdPathInstance) hasSnapshotRecorded(t *testing.T, tid int, c fdPathCase) bool {
	t.Helper()
	var enriched string
	require.Eventually(t, func() bool {
		for _, e := range fdPathEventsOf(i.events, tid, "read") {
			value, numeric, found := fdPathField(e, "fd")
			if found && (value != "" || numeric == int64(c.FD)) {
				enriched = value
				return true
			}
		}
		return false
	}, fdPathWait, 50*time.Millisecond, "read event of thread %d", tid)
	return enriched != ""
}

func Test_FdPathsDisabled(t *testing.T) {
	testutils.AssureIsRoot(t)

	instance := fdPathStart(t, config.OutputConfig{}, fdPathRules("close")...)
	assert.Equal(t, uint32(1), instance.snapshots.MaxEntries(), "a disabled enrichment keeps one entry")

	workload := fdPathRun(t, "paths")
	report := workload.report(t)
	workload.wait(t)
	for _, c := range report.Cases {
		c.Path = ""
		fdPathExpect(t, instance, report.TID, "close", "fd", c)
	}
	assert.Equal(t, fdPathCounts{}, fdPathCountsOf(instance.tracee.Stats()))
	assert.Zero(t, instance.snapshotCount(t))
}

// Filters run on the syscall's numeric argument; the path is output formatting.
func Test_FdPathsNumericFilter(t *testing.T) {
	testutils.AssureIsRoot(t)

	selected := fdPathFirstFD + 1
	instance := fdPathStart(t, config.OutputConfig{FdPaths: true},
		k8s.Rule{Event: "close", Filters: []string{fmt.Sprintf("data.fd=%d", selected)}})

	workload := fdPathRun(t, "paths")
	report := workload.report(t)
	workload.wait(t)
	for _, c := range report.Cases {
		if c.FD == selected {
			fdPathExpect(t, instance, report.TID, "close", "fd", c)
		}
	}
	// Later events would have arrived with the selected one.
	for _, e := range fdPathEventsOf(instance.events, report.TID, "close") {
		enriched, _, _ := fdPathField(e, "fd")
		assert.True(t, strings.HasPrefix(enriched, fmt.Sprintf("%d=", selected)), "filter passed %v", e.Data)
	}
}
