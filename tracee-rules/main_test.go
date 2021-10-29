package main

import (
	"bytes"
	"errors"
	"os"
	"sort"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func Test_listSigs(t *testing.T) {
	fakeSigs := []fakeSignature{
		{
			getMetadata: func() (types.SignatureMetadata, error) {
				return types.SignatureMetadata{
					ID:          "FOO-1",
					Version:     "1.2.3",
					Name:        "foo signature",
					Description: "foo signature helps with foo",
				}, nil
			},
		},
		{
			getMetadata: func() (types.SignatureMetadata, error) {
				return types.SignatureMetadata{
					ID:          "BAR-1",
					Version:     "4.5.6",
					Name:        "bar signature",
					Description: "bar signature helps with bar",
				}, nil
			},
		},
		{
			getMetadata: func() (types.SignatureMetadata, error) {
				return types.SignatureMetadata{}, errors.New("baz failed")
			},
		},
	}

	var inputSigs []types.Signature
	for _, fs := range fakeSigs {
		inputSigs = append(inputSigs, fs)
	}

	buf := bytes.Buffer{}
	assert.NoError(t, listSigs(&buf, inputSigs))
	assert.Equal(t, `ID         NAME                                VERSION DESCRIPTION
FOO-1      foo signature                       1.2.3   foo signature helps with foo
BAR-1      bar signature                       4.5.6   bar signature helps with bar
`, buf.String())
}

func Test_listEvents(t *testing.T) {
	fakeSigs := []fakeSignature{
		{
			getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
				return []types.SignatureEventSelector{
					{
						Source: "tracee",
						Name:   "execve",
						Origin: "foobar",
					},
					{
						Source: "tracee",
						Name:   "ptrace",
						Origin: "bazfoo",
					},
				}, nil
			},
		},
		{
			getSelectedEvents: func() ([]types.SignatureEventSelector, error) {
				return nil, errors.New("failed to list sigs")
			},
		},
	}

	var inputSigs []types.Signature
	for _, fs := range fakeSigs {
		inputSigs = append(inputSigs, fs)
	}

	buf := bytes.Buffer{}
	listEvents(&buf, inputSigs)
	assert.Equal(t, "execve,ptrace\n", buf.String())
}

func Test_dedupSigs(t *testing.T) {
	sig1, _ := regosig.NewRegoSignature("rego", false, `
package tracee.TRC_FOO
import data.tracee.helpers
__rego_metadoc__ := {
    "id": "TRC-FOO"
}
tracee_match {
	input.eventName == "foo"
}`)
	sig2, _ := regosig.NewRegoSignature("rego", false, `
package tracee.TRC_BAR
import data.tracee.helpers
__rego_metadoc__ := {
    "id": "TRC-BAR"
}
tracee_match {
	input.eventName == "bar"
}`)
	require.Equal(t, 2, len(dedupSigs([]types.Signature{sig1, sig2}, []types.Signature{sig2})))
}

func Test_unpackOCIBundle(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		b, _ := os.ReadFile("goldens/sigs-oci-bundle.tar.gz")
		gzf, err := extractGzip(b)
		require.NoError(t, err)
		sigs, err := untarSigs("rego", false, gzf)
		require.NoError(t, err)
		require.Equal(t, 11, len(sigs))
		var gotSigsID []string
		for _, sig := range sigs {
			m, _ := sig.GetMetadata()
			gotSigsID = append(gotSigsID, m.ID)
		}
		sort.Strings(gotSigsID)
		require.Equal(t, []string{"TRC-10", "TRC-11", "TRC-12", "TRC-2", "TRC-3", "TRC-4", "TRC-5", "TRC-6", "TRC-7", "TRC-8", "TRC-9"}, gotSigsID)
	})

	t.Run("invalid Gzip bundle", func(t *testing.T) {
		_, err := extractGzip([]byte("invalid file"))
		require.Equal(t, "unable to read: gzip: invalid header", err.Error())
	})
}
