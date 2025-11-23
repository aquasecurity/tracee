package testutils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/environment"
	uproc "github.com/aquasecurity/tracee/common/proc"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
)

// EventBuffer is a thread-safe buffer for tracee events
type EventBuffer struct {
	mu     sync.RWMutex
	events []*pb.Event
}

func NewEventBuffer() *EventBuffer {
	return &EventBuffer{
		events: make([]*pb.Event, 0),
	}
}

// AddEvent adds an event to the EventBuffer
func (b *EventBuffer) AddEvent(evt *pb.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, evt)
}

// Clear clears the EventBuffer
func (b *EventBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = make([]*pb.Event, 0)
}

// len returns the number of events in the EventBuffer
func (b *EventBuffer) len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.events)
}

// getCopy returns a copy of the eventBuffer events
func (b *EventBuffer) GetCopy() []*pb.Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	evts := make([]*pb.Event, len(b.events))
	copy(evts, b.events)

	return evts
}

// load tracee into memory with args
func StartTracee(ctx context.Context, t *testing.T, cfg config.Config, output *config.OutputConfig, capture *config.CaptureConfig) (*tracee.Tracee, error) {
	initialize.SetLibbpfgoCallbacks()

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return nil, err
	}

	cfg.KernelConfig = kernelConfig

	osInfo, err := environment.GetOSInfo()
	if err != nil {
		return nil, err
	}

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, "/tmp/tracee", "")
	if err != nil {
		return nil, err
	}

	if capture == nil {
		capture = PrepareCapture()
	}

	cfg.Capture = capture

	defaultBufferPages := (4096 * 1024) / os.Getpagesize() // 4 MB of contiguous pages
	cfg.PerfBufferSize = defaultBufferPages
	cfg.BlobPerfBufferSize = defaultBufferPages
	cfg.PipelineChannelSize = 10000

	// No process tree in the integration tests
	cfg.ProcTree = process.ProcTreeConfig{
		Source: process.SourceNone,
	}

	// Disable healthz/heartbeat in integration tests
	// The SignalHeartbeat probe is a uprobe that doesn't work properly when
	// tracee runs as a library in test binaries
	cfg.HealthzEnabled = false

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
	if err != nil {
		return nil, err
	}

	err = trc.Init(ctx)
	if err != nil {
		return nil, err
	}

	go func() {
		err := trc.Run(ctx)
		if err != nil {
			errChan <- fmt.Errorf("error while running tracee: %s", err)
		}
	}()

	return trc, nil
}

// prepareCapture prepares a capture config for tracee
func PrepareCapture() *config.CaptureConfig {
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
func WaitForTraceeStart(trc *tracee.Tracee) error {
	const timeout = 10 * time.Second

	statusCheckTicker := time.NewTicker(1 * time.Second)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-statusCheckTicker.C:
			if trc.Running() {
				return nil
			}
		case <-timeoutTicker.C:
			return errors.New("timed out on waiting for tracee to start")
		}
	}
}

// wait for tracee to stop (or timeout)
// in case of timeout, the test will continue since all tests already passed
func WaitForTraceeStop(trc *tracee.Tracee) error {
	const timeout = 10 * time.Second

	statusCheckTicker := time.NewTicker(1 * time.Second)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-statusCheckTicker.C:
			if !trc.Running() {
				return nil
			}
		case <-timeoutTicker.C:
			return errors.New("timed out on stopping tracee")
		}
	}
}

// wait for tracee buffer to fill up with expected number of events (or timeout)
// in case of timeout, the test will fail
func WaitForTraceeOutputEvents(t *testing.T, waitFor time.Duration, actual *EventBuffer, expectedEvts int, failOnTimeout bool) error {
	if waitFor > 0 {
		t.Logf("  . waiting events collection for %s", waitFor.String())
		time.Sleep(waitFor)
	}

	const timeout = 5 * time.Second

	statusCheckTicker := time.NewTicker(1 * time.Second)
	defer statusCheckTicker.Stop()
	timeoutTicker := time.NewTicker(timeout)
	defer timeoutTicker.Stop()

	t.Logf("  . waiting for at least %d event(s), up to %s", expectedEvts, timeout.String())
	defer t.Logf("  . done waiting for %d event(s)", expectedEvts)

	for {
		select {
		case <-statusCheckTicker.C:
			len := actual.len()
			t.Logf("  . got %d event(s) so far", len)
			if len >= expectedEvts {
				return nil
			}
		case <-timeoutTicker.C:
			if failOnTimeout {
				return fmt.Errorf("timed out on waiting for %d event(s)", expectedEvts)
			}
			return nil
		}
	}
}

// AssureIsRoot skips the test if it is not run as root
func AssureIsRoot(t *testing.T) {
	if syscall.Geteuid() != 0 {
		t.Skipf("***** %s must be run as ROOT *****", t.Name())
	}
}

func GetProcNS(nsName string) string {
	pidInt := syscall.Getpid()
	pid := int32(pidInt)
	nsID, err := uproc.GetProcNS(pid, nsName)
	if err != nil {
		panic(err)
	}

	return strconv.FormatUint(uint64(nsID), 10)
}
