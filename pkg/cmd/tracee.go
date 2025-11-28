package cmd

import (
	"context"
	"os"
	"strconv"
	"syscall"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/fileutil"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
	"github.com/aquasecurity/tracee/pkg/streams"
)

type Runner struct {
	TraceeConfig config.Config
	Workdir      string
	HTTP         *http.Server
	GRPC         *grpc.Server
}

func (r Runner) Run(ctx context.Context) error {
	// Create Tracee Singleton

	t, err := tracee.New(r.TraceeConfig)
	if err != nil {
		return errfmt.Errorf("error creating Tracee: %v", err)
	}

	// Readiness Callback: Tracee is ready to receive events
	t.AddReadyCallback(
		func(ctx context.Context) {
			logger.Debugw("Tracee is ready callback")
			if r.HTTP != nil {
				if r.HTTP.IsMetricsEnabled() {
					if err := t.Stats().RegisterPrometheus(); err != nil {
						logger.Errorw("Registering prometheus metrics", "error", err)
					}
				}
				go r.HTTP.Start(ctx)
			}

			// start server if one is configured
			if r.GRPC != nil {
				go r.GRPC.Start(ctx, t, t.Engine())
			}
		},
	)

	// Need to force nil to allow the garbage
	// collector to free the BPF object
	r.TraceeConfig.BPFObjBytes = nil

	// Initialize tracee

	err = t.Init(ctx)
	if err != nil {
		return errfmt.Errorf("error initializing Tracee: %v", err)
	}

	// Manage PID file

	if err := os.MkdirAll(r.Workdir, 0755); err != nil {
		return errfmt.Errorf("could not create workdir path: %v", err)
	}
	workdir, err := fileutil.OpenExistingDir(r.Workdir)
	if err != nil {
		return errfmt.Errorf("error initializing Tracee: error opening workdir path: %v", err)
	}
	defer func() {
		err := workdir.Close()
		if err != nil {
			logger.Warnw("error closing workdir path", "error", err)
		}
	}()
	if err := writePidFile(workdir); err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := removePidFile(workdir); err != nil {
			logger.Warnw("error removing pid file", "error", err)
		}
	}()

	// Run Tracee

	if r.shouldRunWithPrinter() {
		// Run Tracee with event subscription and printing.
		return r.runWithPrinter(ctx, t) // blocks until ctx is done
	}

	// Printer is inactive, run Tracee without event subscription.
	return t.Run(ctx) // blocks until ctx is done
}

// shouldRunWithPrinter returns true only if there is at least one
// stream with a destination which is not "ignore"
func (r Runner) shouldRunWithPrinter() bool {
	streamConfigs := r.TraceeConfig.Output.Streams
	if len(streamConfigs) == 0 {
		return false
	}

	// It should never happen
	if len(streamConfigs) == 1 && len(streamConfigs[0].Destinations) == 0 {
		return false
	}

	// If the only stream existing has a single destination which is
	// ignore we ignore it and do not even jump to r.runWithPrinter()
	if len(streamConfigs) == 1 && len(streamConfigs[0].Destinations) == 1 &&
		streamConfigs[0].Destinations[0].Type == "ignore" {
		return false
	}

	return true
}

// runWithPrinter runs Tracee with event subscription and printing enabled.
//
// It wraps Tracee's Run method to handle event subscription and printing, and ensures
// that any remaining events are drained when the context is cancelled.
//
// NOTE: This should only be called if at least a stream with a destination exists.
func (r Runner) runWithPrinter(ctx context.Context, t *tracee.Tracee) error {
	streamList := make([]*streams.Stream, 0)
	printers := []printer.EventPrinter{}

	for _, s := range r.TraceeConfig.Output.Streams {
		var p printer.EventPrinter
		var err error

		p, err = printer.New(s.Destinations)
		if err != nil {
			return err
		}
		printers = append(printers, p)

		var stream *streams.Stream
		stream, err = t.Subscribe(s)
		if err != nil {
			return err
		}

		go func() {
			// blocks
			p.FromStream(ctx, stream)
		}()

		streamList = append(streamList, stream)
	}

	// Blocks until ctx is done
	err := t.Run(ctx)

	for _, s := range streamList {
		t.Unsubscribe(s)
	}

	stats := t.Stats()
	for _, p := range printers {
		p.Epilogue(*stats)
		p.Close()
	}

	return err
}

func GetContainerMode(containerFilterEnabled, enrichmentEnabled bool) config.ContainerMode {
	if !containerFilterEnabled {
		return config.ContainerModeDisabled
	}

	// If containers enrichment is disabled, return just enabled mode ...
	if !enrichmentEnabled {
		return config.ContainerModeEnabled
	}

	// ... otherwise return enriched mode as default.
	return config.ContainerModeEnriched
}

const pidFileName = "tracee.pid"

// Initialize PID file
func writePidFile(dir *os.File) error {
	pidFile, err := fileutil.OpenAt(dir, pidFileName, syscall.O_WRONLY|syscall.O_CREAT, 0640)
	if err != nil {
		return errfmt.Errorf("error creating readiness file: %v", err)
	}

	_, err = pidFile.Write([]byte(strconv.Itoa(os.Getpid()) + "\n"))
	if err != nil {
		return errfmt.Errorf("error writing to readiness file: %v", err)
	}

	return nil
}

// Remove PID file
func removePidFile(dir *os.File) error {
	if err := fileutil.RemoveAt(dir, pidFileName, 0); err != nil {
		return errfmt.Errorf("%v", err)
	}

	return nil
}
