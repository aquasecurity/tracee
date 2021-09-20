package regosig

import (
	_ "embed"

	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/compile"
	"github.com/open-policy-agent/opa/rego"
)

var (
	//go:embed aio.rego
	mainRego string
)

const (
	moduleMain             = "main.rego"
	queryMetadataAll       = "data.main.__rego_metadoc_all__"
	querySelectedEventsAll = "data.main.tracee_selected_events_all"
	queryMatchAll          = "data.main.tracee_match_all"
)

// Options holds various Option items that can be passed to the NewAIO constructor.
type Options struct {
	// OPATarget optionally specifies which OPA target engine to use for
	// evaluation. By default, the `rego` engine is used.
	OPATarget string

	// OPAPartial optionally specifies whether to use OPA partial evaluation
	// or not. By default, partial evaluation is disabled.
	//
	// NOTE: On average partial evaluation performs better by leveraging
	// OPA rules indexing. However, for some rules we noticed that enabling partial
	// evaluation significantly degraded performance.
	//
	// https://blog.openpolicyagent.org/partial-evaluation-162750eaf422
	OPAPartial bool
}

type Option func(*Options)

func OPATarget(target string) Option {
	return func(o *Options) {
		o.OPATarget = target
	}
}

func OPAPartial(partial bool) Option {
	return func(o *Options) {
		o.OPAPartial = partial
	}
}

func newDefaultOptions() *Options {
	return &Options{
		OPATarget:  compile.TargetRego,
		OPAPartial: false,
	}
}

type aio struct {
	cb       types.SignatureHandler
	metadata types.SignatureMetadata

	preparedQuery   rego.PreparedEvalQuery
	sigIDToMetadata map[string]types.SignatureMetadata
	selectedEvents  []types.SignatureEventSelector
}

// NewAIO constructs a new types.Signature with the specified Rego modules and Option items.
//
// This implementation compiles all modules once and prepares the single,
// aka all in one, query for evaluation.
func NewAIO(modules map[string]string, opts ...Option) (types.Signature, error) {
	options := newDefaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	modules[moduleMain] = mainRego
	ctx := context.TODO()
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compiling modules: %w", err)
	}

	metadataRS, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(queryMetadataAll),
	).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s query: %w", queryMetadataAll, err)
	}
	sigIDToMetadata, err := MapRS(metadataRS).ToSignatureMetadataAll()
	if err != nil {
		return nil, fmt.Errorf("mapping output to metadata: %w", err)
	}

	selectedEventsRS, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(querySelectedEventsAll),
	).Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s query: %w", querySelectedEventsAll, err)
	}
	sigIDToSelectedEvents, err := MapRS(selectedEventsRS).ToSelectedEventsAll()
	if err != nil {
		return nil, fmt.Errorf("mapping output to selected events: %w", err)
	}

	var peq rego.PreparedEvalQuery

	if options.OPAPartial {
		pr, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(queryMatchAll),
		).PartialResult(ctx)
		if err != nil {
			return nil, fmt.Errorf("partially evaluating %s query: %w", queryMatchAll, err)
		}
		peq, err = pr.Rego(
			rego.Target(options.OPATarget),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("preparing %s query: %w", queryMatch, err)
		}
	} else {
		peq, err = rego.New(
			rego.Target(options.OPATarget),
			rego.Compiler(compiler),
			rego.Query(queryMatchAll),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("preparing %s query: %w", queryMetadataAll, err)
		}
	}

	var sigIDs []string
	var selectedEvents []types.SignatureEventSelector

	selectedEventsSet := make(map[types.SignatureEventSelector]bool)

	for sigID, sigEvents := range sigIDToSelectedEvents {
		sigIDs = append(sigIDs, sigID)

		for _, sigEvent := range sigEvents {
			if _, value := selectedEventsSet[sigEvent]; !value {
				selectedEventsSet[sigEvent] = true
				selectedEvents = append(selectedEvents, sigEvent)
			}
		}
	}

	sort.Strings(sigIDs)
	metadata := types.SignatureMetadata{
		ID:      fmt.Sprintf("TRC-AIO (%s)", strings.Join(sigIDs, ",")),
		Version: "1.0.0",
		Name:    "AIO",
	}

	return &aio{
		metadata:        metadata,
		preparedQuery:   peq,
		sigIDToMetadata: sigIDToMetadata,
		selectedEvents:  selectedEvents,
	}, nil
}

func (a *aio) Init(cb types.SignatureHandler) error {
	a.cb = cb
	return nil
}

func (a *aio) GetMetadata() (types.SignatureMetadata, error) {
	return a.metadata, nil
}

func (a *aio) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return a.selectedEvents, nil
}

func (a *aio) OnEvent(ee types.Event) error {
	input, event, err := toInputOption(ee)
	if err != nil {
		return err
	}

	ctx := context.TODO()
	rs, err := a.preparedQuery.Eval(ctx, input)
	if err != nil {
		return err
	}
	data, err := MapRS(rs).ToDataAll()
	if err != nil {
		return err
	}
	for sigID, value := range data {
		switch v := value.(type) {
		case bool:
			if v {
				a.cb(types.Finding{
					Data:        nil,
					Context:     event,
					SigMetadata: a.sigIDToMetadata[sigID],
				})
			}
		case map[string]interface{}:
			a.cb(types.Finding{
				Data:        v,
				Context:     event,
				SigMetadata: a.sigIDToMetadata[sigID],
			})
		default:
			return fmt.Errorf("unrecognized value: %T", v)
		}
	}
	return nil
}

func toInputOption(ee types.Event) (rego.EvalOption, external.Event, error) {
	var input rego.EvalOption
	var event external.Event

	switch ee.(type) {
	case external.Event:
		event = ee.(external.Event)
		input = rego.EvalInput(ee)
	case engine.ParsedEvent:
		pe := ee.(engine.ParsedEvent)
		event = pe.Event
		input = rego.EvalParsedInput(pe.Value)
	default:
		return nil, external.Event{}, fmt.Errorf("unrecognized event type: %T", ee)
	}
	return input, event, nil
}

func (a *aio) Close() {
	// noop
}

func (a aio) OnSignal(signal types.Signal) error {
	return fmt.Errorf("unsupported operation")
}
