package integration

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/proctree"
	uproc "github.com/aquasecurity/tracee/pkg/utils/proc"
	"github.com/aquasecurity/tracee/types/trace"
)

// eventBuffer is a thread-safe buffer for tracee events
type eventBuffer struct {
	mu     sync.RWMutex
	events []trace.Event
}

func newEventBuffer() *eventBuffer {
	return &eventBuffer{
		events: make([]trace.Event, 0),
	}
}

// addEvent adds an event to the eventBuffer
func (b *eventBuffer) addEvent(evt trace.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, evt)
}

// clear clears the eventBuffer
func (b *eventBuffer) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = make([]trace.Event, 0)
}

// len returns the number of events in the eventBuffer
func (b *eventBuffer) len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.events)
}

// getCopy returns a copy of the eventBuffer events
func (b *eventBuffer) getCopy() []trace.Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	evts := make([]trace.Event, len(b.events))
	copy(evts, b.events)

	return evts
}

// load tracee into memory with args
func startTracee(ctx context.Context, t *testing.T, cfg config.Config, output *config.OutputConfig, capture *config.CaptureConfig) *tracee.Tracee {
	initialize.SetLibbpfgoCallbacks()

	kernelConfig, err := initialize.KernelConfig()
	require.NoError(t, err)

	cfg.KernelConfig = kernelConfig

	osInfo, err := helpers.GetOSInfo()
	require.NoError(t, err)

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, "/tmp/tracee", "")
	require.NoError(t, err)

	if capture == nil {
		capture = prepareCapture()
	}

	cfg.Capture = capture

	cfg.PerfBufferSize = 1024
	cfg.BlobPerfBufferSize = 1024

	// No process tree in the integration tests
	cfg.ProcTree = proctree.ProcTreeConfig{
		Source: proctree.SourceNone,
	}

	errChan := make(chan error)

	go func() {
		for {
			select {
			case err, ok := <-errChan:
				if !ok {
					return
				}
				t.Logf("received error while testing: %s\n", err)
			case <-ctx.Done():
				return
			}
		}
	}()

	if output == nil {
		output = &config.OutputConfig{}
	}

	cfg.Output = output
	cfg.NoContainersEnrich = true

	trc, err := tracee.New(cfg)
	require.NoError(t, err)

	err = trc.Init(ctx)
	require.NoError(t, err)

	go func() {
		err := trc.Run(ctx)
		require.NoError(t, err, "tracee run failed")
	}()

	return trc
}

// prepareCapture prepares a capture config for tracee
func prepareCapture() *config.CaptureConfig {
	// taken from tracee-rule github project, might have to adjust...
	// prepareCapture is called with nil input
	return &config.CaptureConfig{
		FileWrite: config.FileCaptureConfig{
			PathFilter: []string{},
		},
		OutputPath: filepath.Join("/tmp/tracee", "out"),
	}
}

// wait for tracee to start (or timeout)
// in case of timeout, the test will fail
func waitForTraceeStart(t *testing.T, trc *tracee.Tracee) {
	const timeout = 10 * time.Second

	statusCheckTicker := time.NewTicker(100 * time.Millisecond)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-statusCheckTicker.C:
			if trc.Running() {
				t.Logf(">>> started tracee ...")
				return
			}
		case <-timeoutTicker.C:
			t.Logf("timed out on waiting for tracee to start")
			t.FailNow()
		}
	}
}

// wait for tracee to stop (or timeout)
// in case of timeout, the test will continue since all tests already passed
func waitForTraceeStop(t *testing.T, trc *tracee.Tracee) {
	const timeout = 10 * time.Second

	statusCheckTicker := time.NewTicker(100 * time.Millisecond)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-statusCheckTicker.C:
			if !trc.Running() {
				t.Logf("<<< stopped tracee")
				return
			}
		case <-timeoutTicker.C:
			t.Logf("timed out on stopping tracee")
			return
		}
	}
}

// wait for tracee buffer to fill up with expected number of events (or timeout)
// in case of timeout, the test will fail
func waitForTraceeOutputEvents(t *testing.T, actual *eventBuffer, expectedEvts int, failOnTimeout bool) {
	const timeout = 5 * time.Second

	statusCheckTicker := time.NewTicker(100 * time.Millisecond)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	t.Logf("waiting for at least %d event(s) for %s", expectedEvts, timeout.String())
	defer t.Logf("done waiting for %d event(s)", expectedEvts)

	for {
		select {
		case <-statusCheckTicker.C:
			len := actual.len()
			t.Logf("got %d event(s) so far", len)
			if len >= expectedEvts {
				return
			}
		case <-timeoutTicker.C:
			if failOnTimeout {
				t.Logf("timed out on waiting for %d event(s)", expectedEvts)
				t.FailNow()
			}
			return
		}
	}
}

// assureIsRoot skips the test if it is not run as root
func assureIsRoot(t *testing.T) {
	if syscall.Geteuid() != 0 {
		t.Skipf("***** %s must be run as ROOT *****", t.Name())
	}
}

func getProcNS(nsName string) string {
	pid := syscall.Getpid()
	nsID, err := uproc.GetProcNS(uint(pid), nsName)
	if err != nil {
		panic(err)
	}

	return strconv.Itoa(nsID)
}
