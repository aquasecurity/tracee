package regosig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/engine"

	"github.com/open-policy-agent/opa/compile"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMetadata(t *testing.T) {
	testRegoMeta := `
package main

__rego_metadoc__ := {
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

	sig, err := NewRegoSignature(compile.TargetRego, false, testRegoMeta)
	if err != nil {
		t.Error(err)
	}
	expect := types.SignatureMetadata{
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
	if !reflect.DeepEqual(meta, expect) || err != nil {
		t.Error(meta, expect, err)
	}
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
	sig, err := NewRegoSignature(compile.TargetRego, false, testRegoSelectedEvents)
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
		sig, err := NewRegoSignature(compile.TargetRego, false, testRegoBool)
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

	matchedEvent := tracee.Event{
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
	}
	matchedParsedEvent, err := engine.ToParsedEvent(matchedEvent)
	require.NoError(t, err, "parsing event")

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
				matchedEvent,
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
		{
			Events: []types.Event{
				matchedParsedEvent,
			},
			Expect: true,
			CB:     assertFindingData,
		},
	}
	for _, st := range sts {
		sig, err := NewRegoSignature(compile.TargetRego, false, testRegoObj)
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

func TestNewRegoSignature(t *testing.T) {
	var testFiles []string
	err := filepath.Walk("../examples", func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() || strings.Contains(info.Name(), "test") {
			return nil
		}
		testFiles = append(testFiles, path)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(testFiles) // for testability

	var testRegoCodes []string
	for _, f := range testFiles {
		b, err := ioutil.ReadFile(f)
		require.NoError(t, err)
		testRegoCodes = append(testRegoCodes, string(b))
	}

	// assert basic attributes
	for i, rc := range testRegoCodes {
		gotSig, err := NewRegoSignature(compile.TargetRego, false, rc)
		require.NoError(t, err)

		gotMetadata, err := gotSig.GetMetadata()
		require.NoError(t, err)
		assert.Equal(t, types.SignatureMetadata{
			ID:   fmt.Sprintf("FOO-%d", i+1),
			Name: fmt.Sprintf("example%d", i+1),
		}, gotMetadata)

		gotEvents, err := gotSig.GetSelectedEvents()
		require.NoError(t, err)
		assert.Equal(t, []types.SignatureEventSelector{
			{
				Source: "tracee",
			},
		}, gotEvents)
	}
}
