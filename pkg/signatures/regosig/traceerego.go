package regosig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

// RegoSignature is an abstract signature that is implemented in rego
// each struct instance is associated with a rego file
// the rego file declares the following signatures:
// __rego_metadoc__: a *document* rule that defines the rule's metadata (see GetMetadata())
// tracee_selected_events: a *set* rule that defines the event selectors (see GetSelectedEvent())
// tracee_match: a *boolean*, or a *document* rule that defines the logic of the signature (see OnEvent())
type RegoSignature struct {
	cb             detect.SignatureHandler
	compiledRego   *ast.Compiler
	matchPQ        rego.PreparedEvalQuery
	metadata       detect.SignatureMetadata
	selectedEvents []detect.SignatureEventSelector
}

const queryMatch string = "data.%s.tracee_match"
const querySelectedEvents string = "data.%s.tracee_selected_events"
const queryMetadata string = "data.%s.__rego_metadoc__"
const packageNameRegex string = `package\s.*`

// NewRegoSignature creates a new RegoSignature with the provided rego code string
func NewRegoSignature(target string, partialEval bool, regoCodes ...string) (detect.Signature, error) {
	var err error
	res := RegoSignature{}
	regoMap := make(map[string]string)

	re := regexp.MustCompile(packageNameRegex)

	var pkgName string
	for _, regoCode := range regoCodes {
		var regoModuleName string
		splittedName := strings.Split(re.FindString(regoCode), " ")
		if len(splittedName) <= 1 {
			return nil, fmt.Errorf("invalid rego code received")
		}
		regoModuleName = splittedName[1]
		if !strings.Contains(regoCode, "package tracee.helpers") {
			pkgName = regoModuleName
		}
		regoMap[regoModuleName] = regoCode
	}

	res.compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if partialEval {
		pr, err := rego.New(

			rego.Compiler(res.compiledRego),
			rego.Query(fmt.Sprintf(queryMatch, pkgName)),
		).PartialResult(ctx)
		if err != nil {
			return nil, err
		}

		res.matchPQ, err = pr.Rego(rego.Target(target)).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		res.matchPQ, err = rego.New(
			rego.Target(target),
			rego.Compiler(res.compiledRego),
			rego.Query(fmt.Sprintf(queryMatch, pkgName)),
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
}

// Init implements the Signature interface by resetting internal state
func (sig *RegoSignature) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

// GetMetadata implements the Signature interface by evaluating the Rego policy's __rego_metadoc__ rule
// this is a *document* rule that defines the rule's metadata
// based on WIP Rego convention for describing policy metadata: https://hackmd.io/@ZtQnh19kS26YiNlJLqKJnw/H1gAv5nBw
func (sig *RegoSignature) GetMetadata() (detect.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *RegoSignature) getMetadata(pkgName string) (detect.SignatureMetadata, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(queryMetadata, pkgName))
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res detect.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return detect.SignatureMetadata{}, err
	}
	return res, nil
}

// GetSelectedEvents implements the Signature interface by evaluating the Rego policy's tracee_selected_events rule
// this is a *set* rule that defines the rule's SelectedEvents
func (sig *RegoSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return sig.selectedEvents, nil
}

func (sig *RegoSignature) getSelectedEvents(pkgName string) ([]detect.SignatureEventSelector, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(querySelectedEvents, pkgName))
	if err != nil {
		return nil, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return nil, err
	}
	var res []detect.SignatureEventSelector
	err = json.Unmarshal(resJSON, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// OnEvent implements the Signature interface by evaluating the Rego policy's tracee_match rule
// this is a *boolean* or a *document* rule that defines the logic of the signature
// if bool is "returned", a true evaluation will generate a Finding with no data
// if document is "returned", any non-empty evaluation will generate a Finding with the document as the Finding's "Data"
func (sig *RegoSignature) OnEvent(event protocol.Event) error {
	input := rego.EvalInput(event.Payload)
	results, err := sig.matchPQ.Eval(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("evaluating rego: %w", err)
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				sig.cb(&detect.Finding{
					Data:        nil,
					Event:       event,
					SigMetadata: sig.metadata,
				})
			}
		case map[string]interface{}:
			sig.cb(&detect.Finding{
				Data:        v,
				Event:       event,
				SigMetadata: sig.metadata,
			})
		}
	}
	return nil
}

// OnSignal implements the Signature interface by handling lifecycle events of the signature
func (sig *RegoSignature) OnSignal(signal detect.Signal) error {
	return fmt.Errorf("function OnSignal is not implemented")
}

func (sig *RegoSignature) Close() {}

func (sig *RegoSignature) evalQuery(query string) (interface{}, error) {
	pq, err := rego.New(
		rego.Compiler(sig.compiledRego),
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
