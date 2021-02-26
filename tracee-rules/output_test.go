package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

type fakeClock struct {
}

func (fakeClock) Now() time.Time {
	return time.Unix(1614045297, 0)
}

type fakeSignature struct {
	types.Signature
}

func (f fakeSignature) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		ID:          "FOO-666",
		Name:        "foo bar signature",
		Description: "the most evil",
	}, nil
}

func Test_setupOutput(t *testing.T) {
	var testCases = []struct {
		name           string
		inputContext   interface{}
		expectedOutput string
	}{
		{
			name: "happy path with tracee event",
			inputContext: external.Event{
				Timestamp:   12345678,
				ProcessName: "foobar.exe",
				HostName:    "foobar.local",
			},
			expectedOutput: `
*** Detection ***
Time: 2021-02-23T01:54:57Z
Signature ID: FOO-666
Signature: foo bar signature
Data: map[foo1:bar1, baz1 foo2:[bar2 baz2]]
Command: foobar.exe
Hostname: foobar.local
`,
		},
		{
			name: "sad path with unknown context",
			inputContext: struct {
				foo string
			}{foo: "bad input context"},
			expectedOutput: ``,
		},
	}

	for _, tc := range testCases {
		var actualOutput bytes.Buffer
		findingCh, err := setupOutput(&actualOutput, fakeClock{}, "", "")
		require.NoError(t, err, tc.name)

		findingCh <- types.Finding{
			Data: map[string]interface{}{
				"foo1": "bar1, baz1",
				"foo2": []string{"bar2", "baz2"},
			},
			Context:   tc.inputContext,
			Signature: fakeSignature{},
		}

		time.Sleep(time.Millisecond)
		assert.Equal(t, tc.expectedOutput, actualOutput.String(), tc.name)
	}
}

func Test_sendToWebhook(t *testing.T) {
	var testCases = []struct {
		name           string
		inputTemplate  string
		expectedOutput string
	}{
		{
			name:           "happy path, no template JSON output",
			expectedOutput: `{"output":"Rule \"foo bar signature\" detection:\n map[foo1:bar1, baz1 foo2:[bar2 baz2]]","rule":"foo bar signature","time":"2021-02-22T17:54:57-08:00","output_fields":{"value":0}}`,
		},
		{
			name: "happy path, with simple template",
			expectedOutput: `*** Detection ***
Timestamp: 2021-02-27T07:19:07Z
ProcessName: foobar.exe
HostName: foobar.local
`,
			inputTemplate: "templates/simple.tmpl",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				got, _ := ioutil.ReadAll(request.Body)
				assert.Equal(t, tc.expectedOutput, string(got), tc.name)
			}))
			defer ts.Close()

			assert.NoError(t, sendToWebhook(types.Finding{
				Data: map[string]interface{}{
					"foo1": "bar1, baz1",
					"foo2": []string{"bar2", "baz2"},
				},
				Context: external.Event{
					Timestamp:   1614410347,
					ProcessName: "foobar.exe",
					HostName:    "foobar.local",
				},
				Signature: fakeSignature{},
			}, ts.URL, tc.inputTemplate, fakeClock{}), tc.name)
		})
	}
}
