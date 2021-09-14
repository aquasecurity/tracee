package regosig

import (
	"context"
	_ "embed"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

//go:embed aio.rego
var aioRegoCode string

const (
	queryMatchAll = "data.tracee_aio.tracee_match_all"
)

type Options struct {
	PartialEval bool
	Target      string
}

func NewAIORegoSignature(o Options, regoCodes ...string) (types.Signature, error) {
	var err error
	res := RegoSignature{}

	_, regoMap, err := generateRegoMap(regoCodes...)
	if err != nil {
		return nil, err
	}

	regoMap["tracee_aio"] = aioRegoCode
	pkgName := "tracee_aio"

	res.compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if o.PartialEval {
		pr, err := rego.New(
			rego.Compiler(res.compiledRego),
			rego.Query(queryMatchAll),
		).PartialResult(ctx)
		if err != nil {
			return nil, err
		}

		res.matchPQ, err = pr.Rego(rego.Target(o.Target)).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		res.matchPQ, err = rego.New(
			rego.Target(o.Target),
			rego.Compiler(res.compiledRego),
			rego.Query(queryMatchAll),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	}

	res.metadata, err = res.getMetadata(pkgName)
	if err != nil {
		return nil, err
	}
	res.selectedEvents, err = res.getSelectedEvents(pkgName)
	if err != nil {
		return nil, err
	}
	return &res, nil

	return nil, nil
}
