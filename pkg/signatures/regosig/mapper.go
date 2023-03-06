package regosig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/tracee/types/detect"
)

type Mapper struct {
	rego.ResultSet
}

func MapRS(rs rego.ResultSet) *Mapper {
	return &Mapper{
		ResultSet: rs,
	}
}

func (m Mapper) ToSignatureMetadataAll() (map[string]detect.SignatureMetadata, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res map[string]detect.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m Mapper) ToSelectedEventsAll() (map[string][]detect.SignatureEventSelector, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res map[string][]detect.SignatureEventSelector
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m Mapper) ToDataAll() (map[string]interface{}, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	values, ok := m.ResultSet[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unrecognized value: %T", m.ResultSet[0].Expressions[0].Value)
	}
	return values, nil
}

func (m Mapper) isEmpty() bool {
	rs := m.ResultSet
	return len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil
}
