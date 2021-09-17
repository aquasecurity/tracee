package regosig

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

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
		//return nil, err
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

func (aio AIORegoSignature) Init(cb types.SignatureHandler) error {
	panic("implement me")
}

func (aio AIORegoSignature) Close() {
	panic("implement me")
}

func (aio AIORegoSignature) OnEvent(event types.Event) error {
	panic("implement me")
}

func (aio AIORegoSignature) OnSignal(signal types.Signal) error {
	panic("implement me")
}

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
	return &aio, nil
}
