package cmd

import (
	"context"
	"os"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/replay"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
	"github.com/aquasecurity/tracee/pkg/streams"
)

// Runner is the interface for running tracee or replay operations
type Runner interface {
	Run(ctx context.Context) error
}

// TraceeRunner handles running tracee
type TraceeRunner struct {
	TraceeConfig config.Config
	HTTP         *http.Server
	GRPC         *grpc.Server
}

// ReplayRunner handles replaying events from a file
type ReplayRunner struct {
	TraceeConfig config.Config
	ReplayPath   string // File path to replay events from
}

func (r TraceeRunner) Run(ctx context.Context) error {
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
func (r TraceeRunner) shouldRunWithPrinter() bool {
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
func (r TraceeRunner) runWithPrinter(ctx context.Context, t *tracee.Tracee) error {
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
			p.Preamble()

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

// Run implements the Runner interface for ReplayRunner
func (r ReplayRunner) Run(ctx context.Context) error {
	// Validate replay path is set
	if r.ReplayPath == "" {
		return errfmt.Errorf("replay path cannot be empty")
	}

	// Validate file exists and is readable
	sourceFile, err := os.Open(r.ReplayPath)
	if err != nil {
		return errfmt.Errorf("failed to open replay file: %v", err)
	}
	defer func() {
		if closeErr := sourceFile.Close(); closeErr != nil {
			logger.Warnw("Failed to close replay file", "error", closeErr, "file", r.ReplayPath)
		}
	}()

	// Extract detectors from config
	detectorsList := r.TraceeConfig.DetectorConfig.Detectors
	if len(detectorsList) == 0 {
		return errfmt.Errorf("no detectors available")
	}

	// Create dependencies manager for policy manager
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// Create policy manager with empty policies (all events enabled by default)
	policyMgr, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	if err != nil {
		return errfmt.Errorf("failed to create policy manager: %v", err)
	}

	// Enable all detector events (outputs and inputs) in the policy manager
	// This ensures all detectors are available for replay mode
	for _, detector := range detectorsList {
		def := detector.GetDefinition()

		// Enable detector output event (the event this detector produces)
		eventName := def.ProducedEvent.Name
		eventID, found := events.Core.GetDefinitionIDByName(eventName)
		if !found {
			return errfmt.Errorf("detector output event not found in events.Core: detector=%s, event=%s",
				def.ID, eventName)
		}
		policyMgr.EnableEvent(eventID)

		// Enable input events that this detector requires
		for _, req := range def.Requirements.Events {
			eventID := events.LookupPredefinedEventID(req.Name)
			if eventID != 0 {
				policyMgr.EnableEvent(eventID)
			}
		}
	}

	// Enrichment not yet supported in replay mode
	enrichmentOpts := &detectors.EnrichmentOptions{
		Environment:  false,
		ExecHashMode: digest.CalcHashesNone,
		Container:    false,
	}

	// Convert output config to replay-compatible format
	p, err := createReplayPrinter(r.TraceeConfig.Output)
	if err != nil {
		return err
	}

	// Call replay with detectors
	replay.Replay(replay.Config{
		Source:            sourceFile,
		Printer:           p,
		Detectors:         detectorsList,
		PolicyManager:     policyMgr,
		EnrichmentOptions: enrichmentOpts,
	})

	return nil
}

// GetContainerMode returns the container mode based on the container filter enabled and enrichment enabled
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

// createReplayPrinter creates a printer from the output config for replay mode
// If no output is configured, defaults to json:stdout
func createReplayPrinter(outputCfg *config.OutputConfig) (printer.EventPrinter, error) {
	if outputCfg == nil || len(outputCfg.Streams) == 0 {
		// Default to json:stdout if no output configured
		printerCfg, err := flags.PreparePrinterConfig("json", "stdout")
		if err != nil {
			return nil, errfmt.Errorf("failed to prepare default printer config: %v", err)
		}
		p, err := printer.New([]config.Destination{printerCfg})
		if err != nil {
			return nil, errfmt.Errorf("failed to create printer: %v", err)
		}
		return p, nil
	}

	// Note: For now, replay mode only supports a single output stream with a single destination
	firstStream := outputCfg.Streams[0]
	if len(firstStream.Destinations) == 0 {
		return nil, errfmt.Errorf("no destinations in output stream")
	}
	firstDest := firstStream.Destinations[0]

	p, err := printer.New([]config.Destination{firstDest})
	if err != nil {
		return nil, errfmt.Errorf("failed to create printer: %v", err)
	}
	return p, nil
}
