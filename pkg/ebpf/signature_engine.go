package ebpf

import (
	"context"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// engineEvents stage in the pipeline allows signatures detection to be executed in the pipeline
func (t *Tracee) engineEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, t.config.PipelineChannelSize)
	errc := make(chan error, 1)

	engineOutput := make(chan *detect.Finding, t.config.PipelineChannelSize)
	engineInput := make(chan protocol.Event, t.config.PipelineChannelSize)
	engineOutputEvents := make(chan *trace.Event, t.config.PipelineChannelSize)
	source := engine.EventSources{Tracee: engineInput}

	// Prepare built in data sources
	t.config.EngineConfig.DataSources = append(t.config.EngineConfig.DataSources, t.PrepareBuiltinDataSources()...)

	sigEngine, err := engine.NewEngine(t.config.EngineConfig, source, engineOutput)
	if err != nil {
		logger.Fatalw("failed to start signature engine in \"everything is an event\" mode", "error", err)
	}
	t.sigEngine = sigEngine

	if t.config.MetricsEnabled {
		err := t.sigEngine.Stats().RegisterPrometheus()
		if err != nil {
			logger.Errorw("Registering signature engine prometheus metrics", "error", err)
		}
	}

	err = t.sigEngine.Init()
	if err != nil {
		logger.Fatalw("failed to initialize signature engine in \"everything is an event\" mode", "error", err)
	}

	go t.sigEngine.Start(ctx)

	// TODO: in the upcoming releases, the rule engine should be changed to receive trace.Event,
	// and return a trace.Event, which should remove the necessity of converting trace.Event to protocol.Event,
	// and converting detect.Finding into trace.Event

	go func() {
		defer close(out)
		defer close(errc)
		defer close(engineInput)
		defer close(engineOutput)

		// feedEngine feeds an event to the rules engine
		feedEngine := func(event *trace.Event) {
			if event == nil {
				return // might happen during initialization (ctrl+c seg faults)
			}

			id := events.ID(event.EventID)

			// if the event is NOT marked as submit, it is not sent to the rules engine
			if !t.policyManager.IsEventToSubmit(id) {
				return
			}

			// Get a copy of event before parsing it or sending it down the pipeline.
			// This prevents race conditions between the sink stage (which modifies events
			// for output formatting) and the signature engine (which needs raw event data).
			eventCopy := *event

			// Deep copy the Args slice to prevent race conditions during argument parsing
			eventCopy.Args = make([]trace.Argument, len(event.Args))
			copy(eventCopy.Args, event.Args)

			// Ensure ArgsNum matches the actual Args slice length for consistency
			eventCopy.ArgsNum = len(eventCopy.Args)

			// Send original event to sink stage (sink will handle parsing if needed)
			out <- event

			// Send protocol event to signature engine using the safe copy
			engineInput <- eventCopy.ToProtocol()
		}

		for {
			select {
			case event := <-in:
				feedEngine(event)
			case event := <-engineOutputEvents:
				feedEngine(event)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case finding := <-engineOutput:
				if finding == nil {
					return // channel is closed
				}
				if finding.Event.Payload == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}

				event, err := findings.FindingToEvent(finding)
				if err != nil {
					t.handleError(err)
					continue
				}

				if t.matchPolicies(event) == 0 {
					_ = t.stats.EventsFiltered.Increment()
					continue
				}

				engineOutputEvents <- event
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

// PrepareBuiltinDataSources returns a list of all data sources tracee makes available built-in
func (t *Tracee) PrepareBuiltinDataSources() []detect.DataSource {
	datasources := []detect.DataSource{}

	// Containers Data Source
	datasources = append(datasources, containers.NewDataSource(t.containers))

	// DNS Data Source
	if t.config.DNSCacheConfig.Enable {
		datasources = append(datasources, dnscache.NewDataSource(t.dnsCache))
	}

	// Process Tree Data Source
	switch t.config.ProcTree.Source {
	case proctree.SourceNone:
	default:
		datasources = append(datasources, proctree.NewDataSource(t.processTree))
	}

	return datasources
}
