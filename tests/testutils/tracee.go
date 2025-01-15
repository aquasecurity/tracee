package testutils

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

//
// RunningTrace
//

const (
	readinessPollTime           = 200 * time.Millisecond
	httpRequestTimeout          = 1 * time.Second
	TraceeDefaultStartupTimeout = 10 * time.Second
)

var (
	TraceeBinary   = "../../dist/tracee"
	TraceeHostname = "localhost"
	TraceePort     = 3366
)

type TraceeStatus int

const (
	TraceeStarted TraceeStatus = iota
	TraceeFailed
	TraceeTimedout
	TraceeAlreadyRunning
)

// RunningTracee is a wrapper for a running tracee process as a regular process.
type RunningTracee struct {
	ctx       context.Context
	cancel    context.CancelFunc
	cmdStatus chan error
	cmdLine   string
	pid       int
	isReady   chan TraceeStatus
}

// NewRunningTracee creates a new RunningTracee instance.
func NewRunningTracee(givenCtx context.Context, cmdLine string) *RunningTracee {
	ctx, cancel := context.WithCancel(givenCtx)

	// Add healthz flag if not present (required for readiness check)
	if !strings.Contains(cmdLine, "--server http.healthz") {
		cmdLine = fmt.Sprintf("--server http.healthz %s", cmdLine)
	}

	cmdLine = fmt.Sprintf("%s %s", TraceeBinary, cmdLine)

	return &RunningTracee{
		ctx:     ctx,
		cancel:  cancel,
		cmdLine: cmdLine,
	}
}

// Start starts the tracee process.
func (r *RunningTracee) Start(timeout time.Duration) (<-chan TraceeStatus, error) {
	var err error

	imReady := func(s TraceeStatus) {
		go func(s TraceeStatus) {
			r.isReady <- s // blocks until someone reads
		}(s)
	}

	r.isReady = make(chan TraceeStatus)
	now := time.Now()

	if isTraceeAlreadyRunning() { // check if tracee is already running
		imReady(TraceeAlreadyRunning) // ready: already running
		goto exit
	}

	r.pid, r.cmdStatus, err = ExecCmdBgWithSudoAndCtx(r.ctx, r.cmdLine)
	if err != nil {
		imReady(TraceeFailed) // ready: failed
		goto exit
	}

	for {
		time.Sleep(readinessPollTime)
		if r.IsReady() {
			imReady(TraceeStarted) // ready: running
			break
		}
		if time.Since(now) > timeout {
			imReady(TraceeTimedout) // ready: timedout
			break
		}
	}

exit:
	return r.isReady, err
}

// Stop stops the tracee process.
func (r *RunningTracee) Stop() []error {
	if r.pid == 0 {
		return nil // cmd was never started
	}

	r.cancel()
	var errs []error
	for err := range r.cmdStatus {
		errs = append(errs, err)
	}
	return errs
}

// IsReady checks if the tracee process is ready.
func (r *RunningTracee) IsReady() bool {
	ctx, cancel := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancel()

	client := http.Client{
		Timeout: httpRequestTimeout,
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("http://%s:%d/healthz", TraceeHostname, TraceePort),
		nil,
	)
	if err != nil {
		return false
	}

	// Do the request
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	// Only 200 is considered ready
	return resp.StatusCode == 200
}

// isTraceeAlreadyRunning checks if tracee is already running.
func isTraceeAlreadyRunning() bool {
	cmd := exec.Command("pgrep", "tracee")
	cmd.Stderr = nil
	cmd.Stdout = nil

	err := cmd.Run()

	return err == nil
}
