package regosig

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/rego"
)

// RegoSignature is an abstract signature that is implemented in rego
// each struct instance is associated with a rego file
// the rego file declares the following rules:
// __rego_metadoc__: a *document* rule that defines the rule's metadata (see GetMetadata())
// tracee_selected_events: a *set* rule that defines the event selectors (see GetSelectedEvent())
// tracee_match: a *boolean*, or a *document* rule that defines the logic of the signature (see OnEvent())
type RegoSignature struct {
	cb       types.SignatureHandler
	regoCode string
	matchPQ  rego.PreparedEvalQuery
}

const queryMatch string = "data.main.tracee_match"
const querySelectedEvents string = "data.main.tracee_selected_events"
const queryMetadata string = "data.main.__rego_metadoc__"

// NewRegoSignature creates a new RegoSignature with the provided rego code string
func NewRegoSignature(regoCode string) (types.Signature, error) {
	return &RegoSignature{
		regoCode: regoCode,
	}, nil
}

// Init implements the Signature interface by resetting internal state
func (sig *RegoSignature) Init(cb types.SignatureHandler) error {
	var err error
	sig.cb = cb
	sig.matchPQ, err = rego.New(
		rego.Module("sig", sig.regoCode),
		rego.Query(queryMatch),
	).PrepareForEval(context.TODO())
	if err != nil {
		return err
	}
	return nil
}

// GetMetadata implements the Signature interface by evaluating the Rego policy's __rego_metadoc__ rule
// this is a *document* rule that defines the rule's metadata
// based on WIP Rego convention for describing policy metadata: https://hackmd.io/@ZtQnh19kS26YiNlJLqKJnw/H1gAv5nBw
func (sig *RegoSignature) GetMetadata() (types.SignatureMetadata, error) {
	metadataPQ, err := rego.New(
		rego.Module("sig", sig.regoCode),
		rego.Query(queryMetadata),
	).PrepareForEval(context.TODO())
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	results, err := metadataPQ.Eval(context.TODO())
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	var res types.SignatureMetadata
	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		resJSON, err := json.Marshal(results[0].Expressions[0].Value)
		if err != nil {
			return types.SignatureMetadata{}, err
		}
		err = json.Unmarshal(resJSON, &res)
		if err != nil {
			return types.SignatureMetadata{}, err
		}
	}
	return res, nil
}

// GetSelectedEvents implements the Signature interface by evaluating the Rego policy's tracee_selected_events rule
// this is a *set* rule that defines the rule's SelectedEvents
func (sig *RegoSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	eventSelectorPQ, err := rego.New(
		rego.Module("sig", sig.regoCode),
		rego.Query(querySelectedEvents),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}
	results, err := eventSelectorPQ.Eval(context.TODO())
	if err != nil {
		return nil, err
	}
	var res []types.SignatureEventSelector
	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		resJSON, err := json.Marshal(results[0].Expressions[0].Value)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(resJSON, &res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// OnEvent implements the Signature interface by evaluating the Rego policy's tracee_match rule
// this is a *boolean* or a *document* rule that defines the logic of the signature
// if bool is "returned", a true evaluation will generate a Finding with no data
// if document is "returned", any non-empty evaluation will generate a Finding with the document as the Finding's "Data"
func (sig *RegoSignature) OnEvent(e types.Event) error {
	ee, ok := e.(types.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	results, err := sig.matchPQ.Eval(context.TODO(), rego.EvalInput(ee))
	if err != nil {
		return err
	}
	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				sig.cb(types.Finding{
					Data:      nil,
					Context:   ee,
					Signature: sig,
				})
			}
		case map[string]interface{}:
			sig.cb(types.Finding{
				Data:      v,
				Context:   ee,
				Signature: sig,
			})
		}
	}
	return nil
}

// OnSignal implements the Signature interface by handling lifecycle events of the signature
func (sig *RegoSignature) OnSignal(signal types.Signal) error {
	return fmt.Errorf("OnSignal is not implemented")
}
