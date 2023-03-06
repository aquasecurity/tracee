package integration

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/types/trace"
)

// load tracee into memory with args
func startTracee(t *testing.T, ctx context.Context, config tracee.Config, output *tracee.OutputConfig, capture *tracee.CaptureConfig) *tracee.Tracee {
	initialize.SetLibbpfgoCallbacks()

	kernelConfig, err := initialize.KernelConfig()
	require.NoError(t, err)

	config.KernelConfig = kernelConfig

	OSInfo, err := helpers.GetOSInfo()
	require.NoError(t, err)

	err = initialize.BpfObject(&config, kernelConfig, OSInfo, "/tmp/tracee", "")
	require.NoError(t, err)

	if capture == nil {
		capture = prepareCapture()
	}

	config.Capture = capture

	config.PerfBufferSize = 1024
	config.BlobPerfBufferSize = 1024

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
		output = &tracee.OutputConfig{}
	}

	config.Output = output

	trc, err := tracee.New(config)
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

func prepareCapture() *tracee.CaptureConfig {
	// taken from tracee-rule github project, might have to adjust...
	// prepareCapture is called with nil input
	return &tracee.CaptureConfig{
		FilterFileWrite: []string{},
		OutputPath:      filepath.Join("/tmp/tracee", "out"),
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
	const CheckTimeout = 5 * time.Second
	for {
		if gotOutput.len() > 0 {
			break
		}
		if time.Since(now) > CheckTimeout {
			if failOnTimeout {
				t.Logf("timed out on output\n")
				t.FailNow()
			}
			break
		}
	}
}

func waitforTraceeStart(t *testing.T, trc *tracee.Tracee, now time.Time) {
	const CheckTimeout = 10 * time.Second
	for {
		if trc.Running() {
			break
		}
		if time.Since(now) > CheckTimeout {
			t.Logf("timed out on running tracee\n")
			t.FailNow()
		}
	}
}
