package cmd

import (
	"context"
	"os"

	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/analyze"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
	"github.com/aquasecurity/tracee/pkg/streams"
)

// Runner is the interface for running tracee or replay operations
type Runner interface {
	Run(ctx context.Context) error
}

type TraceeRunner struct {
	TraceeConfig config.Config
	HTTP         *http.Server
	GRPC         *grpc.Server
}

// ReplayRunner handles replaying events from a file
type ReplayRunner struct {
	TraceeConfig config.Config
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
	// Get replay file path from viper
	replayPath := viper.GetString("replay")
	if replayPath == "" {
		return errfmt.Errorf("replay path cannot be empty")
	}

	// Validate file exists and is readable
	sourceFile, err := os.Open(replayPath)
	if err != nil {
		return errfmt.Errorf("failed to open replay file: %w", err)
	}
	defer sourceFile.Close()

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
		return errfmt.Errorf("failed to create policy manager: %w", err)
	}

	// IMPORTANT: Enable detector events BEFORE creating the detector engine
	// The dispatcher rebuilds during detector registration and checks IsEventSelected
	// If events aren't enabled yet, detectors won't be added to the dispatch map

	// Enable all detector events (outputs) in the policy manager
	// This ensures all detectors are available for analyze mode
	for _, detector := range detectorsList {
		def := detector.GetDefinition()
		eventName := def.ProducedEvent.Name
		eventID, found := events.Core.GetDefinitionIDByName(eventName)
		if found {
			policyMgr.EnableEvent(eventID)
			logger.Debugw("Enabled detector output event in policy manager",
				"detector", def.ID,
				"event", eventName,
				"event_id", eventID)
		} else {
			logger.Warnw("Detector output event not found in events.Core",
				"detector", def.ID,
				"event", eventName)
		}
	}

	// Enable all input events that detectors require
	// This ensures detectors receive the events they need to process
	for _, detector := range detectorsList {
		def := detector.GetDefinition()
		for _, req := range def.Requirements.Events {
			eventID := events.LookupPredefinedEventID(req.Name)
			if eventID != 0 {
				policyMgr.EnableEvent(eventID)
			}
		}
	}

	// Extract enrichment options from config
	enrichmentOpts := &detectors.EnrichmentOptions{
		ExecEnv:      r.TraceeConfig.EnrichmentEnabled,
		ExecHashMode: digest.CalcHashesNone, // No hash calculation in analyze mode
		Container:    r.TraceeConfig.EnrichmentEnabled,
	}

	// Convert output config to analyze-compatible format
	var p printer.EventPrinter

	outputCfg := r.TraceeConfig.Output
	if outputCfg == nil || len(outputCfg.Streams) == 0 {
		// Default to json:stdout if no output configured
		printerCfg, err := flags.PreparePrinterConfig("json", "stdout")
		if err != nil {
			return errfmt.Errorf("failed to prepare default printer config: %w", err)
		}
		p, err = printer.New([]config.Destination{printerCfg})
		if err != nil {
			return errfmt.Errorf("failed to create printer: %w", err)
		}
	} else {
		// Extract first destination from first stream
		firstStream := outputCfg.Streams[0]
		if len(firstStream.Destinations) == 0 {
			return errfmt.Errorf("no destinations in output stream")
		}
		firstDest := firstStream.Destinations[0]

		// Use the destination directly (no legacy support)
		p, err = printer.New([]config.Destination{firstDest})
		if err != nil {
			return errfmt.Errorf("failed to create printer: %w", err)
		}
	}

	// Call analyze with detectors
	analyze.Analyze(analyze.Config{
		Source:            sourceFile,
		Printer:           p,
		Detectors:         detectorsList,
		PolicyManager:     policyMgr,
		EnrichmentOptions: enrichmentOpts,
	})

	return nil
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
