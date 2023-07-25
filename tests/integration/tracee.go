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
	uproc "github.com/aquasecurity/tracee/pkg/utils/proc"
	"github.com/aquasecurity/tracee/types/trace"
)

// eventBuffer is a thread-safe buffer for tracee events
type eventBuffer struct {
	mu     sync.RWMutex
	events []trace.Event
}

// clear clears the buffer
func (b *eventBuffer) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = b.events[:0]
}

// len returns the number of events in the buffer
func (b *eventBuffer) len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.events)
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

	trc, err := tracee.New(cfg)
	require.NoError(t, err)

	err = trc.Init()
	require.NoError(t, err)

	t.Logf("started tracee...\n")
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

// eventOutput is a thread safe holder for trace events
type eventOutput struct {
	mu     sync.Mutex
	events []trace.Event
}

// addEvent adds an event to the eventOutput
func (e *eventOutput) addEvent(evt trace.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, evt)
}

// getEventsCopy returns a copy of the current events
func (e *eventOutput) getEventsCopy() []trace.Event {
	e.mu.Lock()
	defer e.mu.Unlock()

	events := make([]trace.Event, len(e.events))
	copy(events, e.events)

	return events
}

// len returns the number of the current events
func (e *eventOutput) len() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.events)
}

// wait for tracee buffer to fill or timeout to occur, whichever comes first
func waitForTraceeOutput(t *testing.T, gotOutput *eventOutput, now time.Time, failOnTimeout bool) {
	const checkTimeout = 5 * time.Second
	for {
		if gotOutput.len() > 0 {
			break
		}
		if time.Since(now) > checkTimeout {
			if failOnTimeout {
				t.Logf("timed out on output\n")
				t.FailNow()
			}
			break
		}
	}
}

// wait for tracee to start (or timeout)
// in case of timeout, the test will fail
func waitForTraceeStart(t *testing.T, trc *tracee.Tracee) {
	const checkTimeout = 10 * time.Second
	ticker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			if trc.Running() {
				return
			}
		case <-time.After(checkTimeout):
			t.Logf("timed out on running tracee\n")
			t.FailNow()
		}
	}
}

// wait for tracee to stop (or timeout)
// in case of timeout, the test will continue since all tests already passed
func waitForTraceeStop(t *testing.T, trc *tracee.Tracee) {
	const checkTimeout = 10 * time.Second
	ticker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			if !trc.Running() {
				t.Logf("stopped tracee\n")
				return
			}
		case <-time.After(checkTimeout):
			t.Logf("timed out on stopping tracee\n")
			return
		}
	}
}

// wait for tracee buffer to fill up with expected number of events (or timeout)
// in case of timeout, the test will fail
func waitForTraceeOutputEvents(t *testing.T, actual *eventBuffer, now time.Time, expectedEvts int, failOnTimeout bool) {
	const checkTimeout = 5 * time.Second
	ticker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			if actual.len() >= expectedEvts {
				return
			}
		case <-time.After(checkTimeout):
			if failOnTimeout {
				t.Logf("timed out on output\n")
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
