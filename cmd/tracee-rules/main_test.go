package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

func Test_listSigs(t *testing.T) {
	t.Parallel()

	fakeSigs := []*signature.FakeSignature{
		{
			FakeGetMetadata: func() (detect.SignatureMetadata, error) {
				return detect.SignatureMetadata{
					ID:          "FOO-1",
					Version:     "1.2.3",
					Name:        "foo signature",
					Description: "foo signature helps with foo",
				}, nil
			},
		},
		{
			FakeGetMetadata: func() (detect.SignatureMetadata, error) {
				return detect.SignatureMetadata{
					ID:          "BAR-1",
					Version:     "4.5.6",
					Name:        "bar signature",
					Description: "bar signature helps with bar",
				}, nil
			},
		},
		{
			FakeGetMetadata: func() (detect.SignatureMetadata, error) {
				return detect.SignatureMetadata{}, errors.New("baz failed")
			},
		},
	}

	var inputSigs []detect.Signature
	for _, fs := range fakeSigs {
		inputSigs = append(inputSigs, fs)
	}

	buf := bytes.Buffer{}
	listSigs(&buf, inputSigs)
	assert.Equal(t, `ID         NAME                                VERSION DESCRIPTION
FOO-1      foo signature                       1.2.3   foo signature helps with foo
BAR-1      bar signature                       4.5.6   bar signature helps with bar
`, buf.String())
}

func Test_listEvents(t *testing.T) {
	t.Parallel()

	fakeSigs := []*signature.FakeSignature{
		{
			FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
				return []detect.SignatureEventSelector{
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
			FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
				return nil, errors.New("failed to list sigs")
			},
		},
	}

	var inputSigs []detect.Signature
	for _, fs := range fakeSigs {
		inputSigs = append(inputSigs, fs)
	}

	buf := bytes.Buffer{}
	listEvents(&buf, inputSigs)
	assert.Equal(t, "execve,ptrace\n", buf.String())
}
