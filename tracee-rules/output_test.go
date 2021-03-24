package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
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
		outputFormat   string
		expectedOutput string
	}{
		{
			name: "happy path with tracee event and default output",
			inputContext: external.Event{
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
			name: "happy path with tracee event and simple custom output template",
			inputContext: external.Event{
				ProcessName: "foobar.exe",
				HostName:    "foobar.local",
			},
			expectedOutput: `*** Detection ***
Timestamp: 2021-02-23T01:54:57Z
ProcessName: foobar.exe
HostName: foobar.local
`,
			outputFormat: "templates/simple.tmpl",
		},
		{
			name: "sad path with unknown context",
			inputContext: struct {
				foo string
			}{foo: "bad input context"},
			expectedOutput: ``,
		},
		{
			name: "sad path with invalid custom template",
			inputContext: external.Event{
				ProcessName: "foobar.exe",
				HostName:    "foobar.local",
			},
			outputFormat: "goldens/broken.tmpl",
		},
	}

	for _, tc := range testCases {
		var actualOutput bytes.Buffer
		findingCh, err := setupOutput(&actualOutput, "", "", "", tc.outputFormat)
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
		checkOutput(t, tc.name, actualOutput, tc.expectedOutput)
	}
}

func checkOutput(t *testing.T, testName string, actualOutput bytes.Buffer, expectedOutput string) {
	got := strings.Split(actualOutput.String(), "\n")
	for _, g := range got {
		if strings.Contains(g, "Time") {
			_, err := time.Parse("2006-01-02T15:04:05Z", strings.Split(g, " ")[1])
			assert.NoError(t, err, testName) // check if time is parsable
		} else {
			assert.Contains(t, expectedOutput, g, testName)
		}
	}
}

func Test_sendToWebhook(t *testing.T) {
	var testCases = []struct {
		name               string
		inputTemplateFile  string
		inputSignature     fakeSignature
		inputTestServerURL string
		contentType        string
		expectedOutput     string
		expectedError      string
	}{
		{
			name:           "happy path, no template JSON output",
			contentType:    "application/json",
			expectedOutput: `{"output":"Rule \"foo bar signature\" detection:\n map[foo1:bar1, baz1 foo2:[bar2 baz2]]","rule":"foo bar signature","time":"2021-02-23T01:54:57Z","output_fields":{"value":0}}`,
		},
		{
			name:        "happy path, with simple template",
			contentType: "text/plain",
			expectedOutput: `*** Detection ***
Timestamp: 2021-02-23T01:54:57Z
ProcessName: foobar.exe
HostName: foobar.local
`,
			inputTemplateFile: "templates/simple.tmpl",
		},
		{
			name:        "happy path with functions from sprig template",
			contentType: "text/plain",
			expectedOutput: `{
  "foo1": "bar1, baz1",
  "foo2": [
    "bar2",
    "baz2"
  ]
}`,
			inputTemplateFile: "templates/sprig.tmpl",
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
			expectedError:     `error writing to template: template not initialized`,
		},
		{
			name:              "sad path, with an invalid template",
			contentType:       "application/foo",
			inputTemplateFile: "goldens/broken.tmpl",
			expectedError:     `error writing to the template: template: broken.tmpl:1:3: executing "broken.tmpl" at <.InvalidField>: can't evaluate field InvalidField in type types.Finding`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				got, _ := ioutil.ReadAll(request.Body)
				checkOutput(t, tc.name, *bytes.NewBuffer(got), tc.expectedOutput)
				assert.Equal(t, tc.contentType, request.Header.Get("content-type"), tc.name)
			}))
			defer ts.Close()

			if tc.inputTestServerURL != "" {
				ts.URL = tc.inputTestServerURL
			}

			inputTemplate, _ := setupTemplate(tc.inputTemplateFile)

			actualError := sendToWebhook(inputTemplate, types.Finding{
				Data: map[string]interface{}{
					"foo1": "bar1, baz1",
					"foo2": []string{"bar2", "baz2"},
				},
				Context: external.Event{
					ProcessName: "foobar.exe",
					HostName:    "foobar.local",
				},
				Signature: tc.inputSignature,
			}, ts.URL, tc.inputTemplateFile, tc.contentType, fakeClock{})

			switch {
			case tc.expectedError != "":
				assert.EqualError(t, actualError, tc.expectedError, tc.name)
			default:
				assert.NoError(t, actualError, tc.name)
			}
		})

	}
}
