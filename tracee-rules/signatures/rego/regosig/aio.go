package regosig

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/engine"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

//go:embed aio.rego
var aioRegoCode string

const (
	queryMatchAll                 = "data.tracee_aio.tracee_match_all"
	querySelectedEventsAll string = "data.tracee_aio.tracee_selected_events_all"
	queryMetadataAll       string = "data.tracee_aio.__rego_metadoc_all__"
)

type AIORegoSignature struct {
	cb                    types.SignatureHandler
	index                 index
	compiledRego          *ast.Compiler
	matchPQ               rego.PreparedEvalQuery
	sigIDToMetadata       map[string]types.SignatureMetadata
	sigIDToSelectedEvents map[string][]types.SignatureEventSelector
}

func (aio AIORegoSignature) evalQuery(query string) (interface{}, error) {
	pq, err := rego.New(
		rego.Compiler(aio.compiledRego),
		rego.Query(query),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}
	evalRes, err := pq.Eval(context.TODO())
	if err != nil {
		return nil, err
	}
	if len(evalRes) > 0 && len(evalRes[0].Expressions) > 0 && evalRes[0].Expressions[0].Value != nil {
		return evalRes[0].Expressions[0].Value, nil
	}
	return nil, nil
}

func (aio *AIORegoSignature) getMetadata(pkgName string) (types.SignatureMetadata, error) {
	evalRes, err := aio.evalQuery(fmt.Sprintf(queryMetadata, pkgName))
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res types.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	return res, nil
}

// TODO: Breaking change with current Signature/GetMetadata implementation
func (aio AIORegoSignature) GetMetadata(sigID string) (types.SignatureMetadata, error) {
	return aio.sigIDToMetadata[sigID], nil
}

func (aio *AIORegoSignature) getSelectedEvents(pkgName string) ([]types.SignatureEventSelector, error) {
	evalRes, err := aio.evalQuery(fmt.Sprintf(querySelectedEvents, pkgName))
	if err != nil {
		return nil, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res []types.SignatureEventSelector
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// TODO: Breaking change with current Signature/GetSelectedEvents implementation
func (aio AIORegoSignature) GetSelectedEvents(sigID string) ([]types.SignatureEventSelector, error) {
	return aio.sigIDToSelectedEvents[sigID], nil
}

func (aio *AIORegoSignature) Init(cb types.SignatureHandler) error {
	aio.cb = cb
	return nil
}

func (aio *AIORegoSignature) dispatch(val interface{}, ee tracee.Event, sigIDs []string) {
	for _, sigID := range sigIDs {
		switch v := val.(type) {
		case bool:
			if v {
				aio.cb(types.Finding{
					Data:        nil,
					Context:     ee,
					SigMetadata: aio.sigIDToMetadata[sigID],
				})
			}
		case map[string]interface{}:
			aio.cb(types.Finding{
				Data:        v,
				Context:     ee,
				SigMetadata: aio.sigIDToMetadata[sigID],
			})
		case string:
			aio.cb(types.Finding{
				Data:        map[string]interface{}{sigID: val},
				Context:     ee,
				SigMetadata: aio.sigIDToMetadata[sigID],
			})
		}
	}

}

func (aio AIORegoSignature) OnEvent(e types.Event) error {
	var input rego.EvalOption
	var ee tracee.Event

	switch v := e.(type) {
	// This case is for backward compatibility. From OPA Go SDK standpoint it's more efficient to enter ParsedEvent case.
	case tracee.Event:
		ee = e.(tracee.Event)
		input = rego.EvalInput(e)
	case engine.ParsedEvent:
		pe := e.(engine.ParsedEvent)
		ee = pe.Event
		input = rego.EvalParsedInput(pe.Value)
	default:
		return fmt.Errorf("unrecognized event type: %T", v)
	}
	results, err := aio.matchPQ.Eval(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("evaluating rego: %w", err)
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {

		sigIDs := aio.index.getSignaturesMatchingEvent(ee)
		switch results[0].Expressions[0].Value.(type) {
		case map[string]interface{}:
			values, ok := results[0].Expressions[0].Value.(map[string]interface{})
			if ok && len(values) <= 0 {
				return nil
			} else {
				aio.dispatch(values, ee, sigIDs)
			}
		case bool:
			aio.dispatch(results[0].Expressions[0].Value, ee, sigIDs)
		}

		// TODO: Check if still needed
		// For AIO: result set can be an empty set of length=1, so we need to check value
		//values, ok := results[0].Expressions[0].Value.(map[string]interface{})
		//if ok && len(values) <= 0 {
		//	return nil
		//}
		//aio.dispatch(values, ee, sigIDs)
	}
	return nil
}

func (aio AIORegoSignature) OnSignal(signal types.Signal) error {
	return fmt.Errorf("function OnSignal is not implemented")
}
func (aio AIORegoSignature) Close() {}

type Options struct {
	PartialEval bool
	Target      string
}

func NewAIORegoSignature(o Options, regoCodes ...string) (types.SignatureV2, error) {
	var err error
	aio := AIORegoSignature{
		sigIDToMetadata:       make(map[string]types.SignatureMetadata),
		sigIDToSelectedEvents: make(map[string][]types.SignatureEventSelector),
	}

	_, regoMap, err := GenerateRegoMap(regoCodes...)
	if err != nil {
		return nil, err
	}
	regoMap["tracee_aio"] = aioRegoCode

	aio.compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if o.PartialEval {
		pr, err := rego.New(
			rego.Compiler(aio.compiledRego),
			rego.Query(queryMatchAll),
		).PartialResult(ctx)
		if err != nil {
			return nil, err
		}

		aio.matchPQ, err = pr.Rego(rego.Target(o.Target)).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		aio.matchPQ, err = rego.New(
			rego.Target(o.Target),
			rego.Compiler(aio.compiledRego),
			rego.Query(queryMatchAll),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	}

	for sigId, _ := range regoMap {
		aio.sigIDToMetadata[sigId], err = aio.getMetadata(sigId)
		if err != nil {
			return nil, err
		}
	}

	for sigId, _ := range regoMap {
		aio.sigIDToSelectedEvents[sigId], err = aio.getSelectedEvents(sigId)
		if err != nil {
			return nil, err
		}
	}
	aio.index = newIndex(aio.sigIDToSelectedEvents)
	return &aio, nil
}
