package ebpf

import (
	"context"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/dnscache"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
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

	engineOutput := make(chan *detect.Finding, 10000)
	engineInput := make(chan protocol.Event, 10000)
	engineOutputEvents := make(chan *trace.Event, t.config.PipelineChannelSize)
	source := engine.EventSources{Tracee: engineInput}

	// Prepare built in data sources
	t.config.EngineConfig.DataSources = append(t.config.EngineConfig.DataSources, t.PrepareBuiltinDataSources()...)

	// Share event states (by reference)
	t.config.EngineConfig.ShouldDispatchEvent = func(eventIdInt32 int32) bool {
		_, ok := t.eventsState[events.ID(eventIdInt32)]
		return ok
	}

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

	// Create a function for feeding the engine with an event
	feedFunc := func(event *trace.Event) {
		if event == nil {
			return // might happen during initialization (ctrl+c seg faults)
		}

		id := events.ID(event.EventID)

		// if the event is marked as submit, we pass it to the engine
		if t.eventsState[id].Submit > 0 {
			err := t.parseArguments(event)
			if err != nil {
				t.handleError(err)
				return
			}

			// Get a copy of our event before sending it down the pipeline.
			// This is needed because a later modification of the event (in
			// particular of the matched policies) can affect engine stage.
			eventCopy := *event
			// pass the event to the sink stage, if the event is also marked as emit
			// it will be sent to print by the sink stage
			out <- event

			// send the event to the rule event
			engineInput <- eventCopy.ToProtocol()
		}
	}

	// TODO: in the upcoming releases, the rule engine should be changed to receive trace.Event,
	// and return a trace.Event, which should remove the necessity of converting trace.Event to protocol.Event,
	// and converting detect.Finding into trace.Event

	go func() {
		defer close(out)
		defer close(errc)
		defer close(engineInput)
		defer close(engineOutput)

		for {
			select {
			case event := <-in:
				feedFunc(event)
			case event := <-engineOutputEvents:
				feedFunc(event)
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

				event, err := FindingToEvent(finding)
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
