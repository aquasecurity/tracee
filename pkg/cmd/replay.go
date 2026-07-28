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
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/replay"
)

// ReplayRunner handles replaying events from a file
type ReplayRunner struct {
	TraceeConfig config.Config
	ReplayPath   string // File path to replay events from
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

	// Create a policy manager with no policies: nothing is selected until
	// events are explicitly enabled below, and the detector dispatcher only
	// routes events the policy manager reports as selected
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
			// Not LookupPredefinedEventID: its 0 return is ambiguous with the
			// read event (internal ID 0), which would never get enabled
			reqEventID, found := events.Core.GetDefinitionIDByName(req.Name)
			if !found {
				logger.Warnw("Detector required event not found, skipping",
					"detector", def.ID, "event", req.Name)
				continue
			}
			policyMgr.EnableEvent(reqEventID)
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
	return replay.Replay(ctx, replay.Config{
		Source:            sourceFile,
		Printer:           p,
		Detectors:         detectorsList,
		PolicyManager:     policyMgr,
		EnrichmentOptions: enrichmentOpts,
	})
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

	// For now, replay mode only supports a single output stream with a
	// single destination. Silently dropping extra outputs could lose an
	// alerting sink (e.g. a webhook), so reject them outright.
	firstStream := outputCfg.Streams[0]
	if len(firstStream.Destinations) == 0 {
		return nil, errfmt.Errorf("no destinations in output stream")
	}
	if len(outputCfg.Streams) > 1 || len(firstStream.Destinations) > 1 {
		return nil, errfmt.Errorf("replay mode supports a single output destination, got %d stream(s) with %d destination(s) in the first",
			len(outputCfg.Streams), len(firstStream.Destinations))
	}

	p, err := printer.New([]config.Destination{firstStream.Destinations[0]})
	if err != nil {
		return nil, errfmt.Errorf("failed to create printer: %v", err)
	}
	return p, nil
}
