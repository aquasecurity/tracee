package cmd

import (
	"context"
	"os"
	"strconv"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Runner struct {
	TraceeConfig config.Config
	Printer      *printer.Broadcast
	InstallPath  string
	HTTPServer   *http.Server
	GRPCServer   *grpc.Server
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
			if r.HTTPServer != nil {
				if r.HTTPServer.MetricsEndpointEnabled() {
					r.TraceeConfig.MetricsEnabled = true // TODO: is this needed ?
					if err := t.Stats().RegisterPrometheus(); err != nil {
						logger.Errorw("Registering prometheus metrics", "error", err)
					}
				}
				go r.HTTPServer.Start(ctx)
			}

			// start server if one is configured
			if r.GRPCServer != nil {
				go r.GRPCServer.Start(ctx, t, t.Engine())
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

	if err := os.MkdirAll(r.InstallPath, 0755); err != nil {
		return errfmt.Errorf("could not create install path dir: %v", err)
	}
	installPathDir, err := utils.OpenExistingDir(r.InstallPath)
	if err != nil {
		return errfmt.Errorf("error initializing Tracee: error opening installation path: %v", err)
	}
	defer func() {
		err := installPathDir.Close()
		if err != nil {
			logger.Warnw("error closing install path dir", "error", err)
		}
	}()
	if err := writePidFile(installPathDir); err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		if err := removePidFile(installPathDir); err != nil {
			logger.Warnw("error removing pid file", "error", err)
		}
	}()

	// Run Tracee

	if r.Printer.Active() {
		// Run Tracee with event subscription and printing.
		return r.runWithPrinter(ctx, t) // blocks until ctx is done
	}

	// Printer is inactive, run Tracee without event subscription.
	return t.Run(ctx) // blocks until ctx is done
}

// runWithPrinter runs Tracee with event subscription and printing enabled.
//
// It wraps Tracee's Run method to handle event subscription and printing, and ensures
// that any remaining events are drained when the context is cancelled.
//
// NOTE: This should only be called if a printer is active.
func (r Runner) runWithPrinter(ctx context.Context, t *tracee.Tracee) error {
	stream := t.SubscribeAll()
	defer t.Unsubscribe(stream)

	r.Printer.Preamble()

	// Start goroutine to print incoming events
	go func() {
		for {
			select {
			case event := <-stream.ReceiveEvents():
				r.Printer.Print(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Blocks until ctx is done
	err := t.Run(ctx)

	// Drain remaining channel events (sent during shutdown)
	for event := range stream.ReceiveEvents() {
		r.Printer.Print(event)
	}

	stats := t.Stats()
	r.Printer.Epilogue(*stats)
	r.Printer.Close()

	return err
}

func GetContainerMode(containerFilterEnabled, noContainersEnrich bool) config.ContainerMode {
	if !containerFilterEnabled {
		return config.ContainerModeDisabled
	}

	// If containers enrichment is disabled, return just enabled mode ...
	if noContainersEnrich {
		return config.ContainerModeEnabled
	}

	// ... otherwise return enriched mode as default.
	return config.ContainerModeEnriched
}

const pidFileName = "tracee.pid"

// Initialize PID file
func writePidFile(dir *os.File) error {
	pidFile, err := utils.OpenAt(dir, pidFileName, syscall.O_WRONLY|syscall.O_CREAT, 0640)
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
	if err := utils.RemoveAt(dir, pidFileName, 0); err != nil {
		return errfmt.Errorf("%v", err)
	}

	return nil
}
