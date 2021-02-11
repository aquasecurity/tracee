package regosig

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

func TestGetMetadata(t *testing.T) {
	testRegoMeta := `
package main

__rego_metadoc__ := {
	"id": "TRC-12345",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}
`
	sig, err := NewRegoSignature(testRegoMeta)
	require.NoError(t, err)

	expect := types.SignatureMetadata{
		ID:          "TRC-12345",
		Name:        "test name",
		Description: "test description",
		Tags:        []string{"tag1", "tag2"},
		Properties: map[string]interface{}{
			"p1": "test",
			"p2": json.Number("1"),
			"p3": true,
		},
	}
	meta, err := sig.GetMetadata()
	require.NoError(t, err)
	assert.Equal(t, expect, meta)
}

func TestGetSelectedEvents(t *testing.T) {
	testRegoSelectedEvents := `
package main

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}
`
	sig, err := NewRegoSignature(testRegoSelectedEvents)
	if err != nil {
		t.Error(err)
	}
	expect := []types.SignatureEventSelector{{
		Source: "tracee",
	}}
	meta, err := sig.GetSelectedEvents()
	if !reflect.DeepEqual(meta, expect) || err != nil {
		t.Error(meta, expect, err)
	}
}

func TestOnEventBool(t *testing.T) {
	testRegoBool := `
package main

tracee_match {
	endswith(input.args[0].value, "yo")
}
`
	sts := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter"},
							Value: "doesn't end with yo!",
						},
					},
				},
			},
			Expect: false,
		},
	}
	for _, st := range sts {
		sig, err := NewRegoSignature(testRegoBool)
		if err != nil {
			t.Error(err)
		}
		st.Init(sig)
		for _, e := range st.Events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}
		if st.Expect != st.Status {
			t.Error("unexpected result", st)
		}
	}
}

func TestOnEventObj(t *testing.T) {
	testRegoObj := `
package main

tracee_match = res {
	endswith(input.args[0].value, "yo")
	input.args[1].value == 1337
	res := {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}
`
	assertFindingData := func(res types.Finding) {
		expectedFindingData := map[string]interface{}{
			"p1": "test",
			"p2": json.Number("1"),
			"p3": true,
		}
		if !reflect.DeepEqual(res.Data, expectedFindingData) {
			t.Errorf("finding data mismatch. want %v, have %+v", expectedFindingData, res.Data)
		}
	}
	sts := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				},
			},
			Expect: false,
			CB:     assertFindingData,
		},
		{
			Events: []types.Event{
				tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: 1337,
						},
					},
				},
			},
			Expect: true,
			CB:     assertFindingData,
		},
		{
			Events: []types.Event{
				tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "yo is not at end",
						},
					},
				},
			},
			Expect: false,
			CB:     assertFindingData,
		},
	}
	for _, st := range sts {
		sig, err := NewRegoSignature(testRegoObj)
		if err != nil {
			t.Error(err)
		}
		st.Init(sig)
		for _, e := range st.Events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}
		if st.Expect != st.Status {
			t.Error("unexpected result", st)
		}
	}
}
