package main

import (
	"bytes"
	"errors"
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
	getMetadata func() (types.SignatureMetadata, error)
}

func (f fakeSignature) GetMetadata() (types.SignatureMetadata, error) {
	if f.getMetadata != nil {
		return f.getMetadata()
	}

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
		name               string
		inputTemplateFile  string
		inputSignature     fakeSignature
		inputTestServerURL string
		expectedOutput     string
		expectedError      string
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
			inputTemplateFile: "templates/simple.tmpl",
		},
		{
			name:              "happy path, with CSV template",
			expectedOutput:    `2021-02-27T07:19:07Z,foobar.exe,foobar.local`,
			inputTemplateFile: "templates/csv.tmpl",
		},
		{
			name: "happy path, with XML template",
			expectedOutput: `<?xml version="1.0" encoding="UTF-8" ?>
 <detection timestamp="2021-02-27T07:19:07Z">
    <processname>foobar.exe</processname>
    <hostname>foobar.local</hostname>
 </detection>`,
			inputTemplateFile: "templates/xml.tmpl",
		},
		{
			name: "sad path, with failing GetMetadata func for sig",
			inputSignature: fakeSignature{
				getMetadata: func() (types.SignatureMetadata, error) {
					return types.SignatureMetadata{}, errors.New("getMetadata failed")
				},
			},
			expectedError: "error preparing json payload: getMetadata failed",
		},
		{
			name:               "sad path, error reaching webhook",
			inputTestServerURL: "foo://bad.host",
			expectedError:      `error calling webhook Post "foo://bad.host": unsupported protocol scheme "foo"`,
		},
		{
			name:              "sad path, with missing template",
			inputTemplateFile: "invalid/template",
			expectedError:     `error preparing webhook template: open invalid/template: no such file or directory`,
		},
		{
			name:              "sad path, with an invalid template",
			inputTemplateFile: "goldens/broken.tmpl",
			expectedError:     `error writing to the template: template: broken.tmpl:1:3: executing "broken.tmpl" at <.InvalidField>: can't evaluate field InvalidField in type types.Finding`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				got, _ := ioutil.ReadAll(request.Body)
				assert.Equal(t, tc.expectedOutput, string(got), tc.name)
			}))
			defer ts.Close()

			if tc.inputTestServerURL != "" {
				ts.URL = tc.inputTestServerURL
			}

			actualError := sendToWebhook(types.Finding{
				Data: map[string]interface{}{
					"foo1": "bar1, baz1",
					"foo2": []string{"bar2", "baz2"},
				},
				Context: external.Event{
					Timestamp:   1614410347,
					ProcessName: "foobar.exe",
					HostName:    "foobar.local",
				},
				Signature: tc.inputSignature,
			}, ts.URL, tc.inputTemplateFile, fakeClock{})

			switch {
			case tc.expectedError != "":
				assert.EqualError(t, actualError, tc.expectedError, tc.name)
			default:
				assert.NoError(t, actualError, tc.name)
			}
		})

	}
}
