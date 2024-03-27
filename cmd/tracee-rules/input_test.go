package main

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestParseTraceeInputOptions(t *testing.T) {
	testCases := []struct {
		testName              string
		optionStringSlice     []string
		expectedResultOptions *traceeInputOptions
		expectedError         error
	}{
		{
			testName:              "no options specified",
			optionStringSlice:     []string{},
			expectedResultOptions: nil,
			expectedError:         errors.New("no tracee input options specified"),
		},
		{
			testName:              "non-existent file specified",
			optionStringSlice:     []string{"file:/iabxfdoabs22do2b"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid Tracee input file: /iabxfdoabs22do2b"),
		},
		{
			testName:              "non-existent file specified",
			optionStringSlice:     []string{"file:/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid Tracee input file: /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
		{
			testName:              "non-existent file specified",
			optionStringSlice:     []string{"file:"},
			expectedResultOptions: nil,
			expectedError:         errors.New("empty key or value passed: key: >file< value: ><"),
		},
		{
			testName:              "invalid file format specified",
			optionStringSlice:     []string{"format:xml"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid tracee input format specified: XML"),
		},
		{
			testName:              "invalid input option specified",
			optionStringSlice:     []string{"shmoo:hallo"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid input-tracee option key: shmoo"),
		},
		{
			testName:              "invalid input option specified",
			optionStringSlice:     []string{":"},
			expectedResultOptions: nil,
			expectedError:         errors.New("empty key or value passed: key: >< value: ><"),
		},
		{
			testName:              "invalid input option specified",
			optionStringSlice:     []string{"A"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid input-tracee option: A"),
		},
		{
			testName:              "invalid input option specified",
			optionStringSlice:     []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid input-tracee option: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
		{
			testName:              "invalid input option specified",
			optionStringSlice:     []string{"3O$B@4420**@!;;;go.fmt@!3h;^!#!@841083n1"},
			expectedResultOptions: nil,
			expectedError:         errors.New("invalid input-tracee option: 3O$B@4420**@!;;;go.fmt@!3h;^!#!@841083n1"),
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			opt, err := parseTraceeInputOptions(testcase.optionStringSlice)
			assert.ErrorContains(t, err, testcase.expectedError.Error())
			assert.Equal(t, testcase.expectedResultOptions, opt)
		})
	}
}

func TestSetupTraceeJSONInputSource(t *testing.T) {
	testCases := []struct {
		testName      string
		events        []trace.Event
		expectedError error
	}{
		{
			testName: "one event",
			events: []trace.Event{
				{
					EventName: "Yankees are the best team in baseball",
				},
			},
			expectedError: nil,
		},
		{
			testName: "two events",
			events: []trace.Event{
				{
					EventName: "Yankees are the best team in baseball",
				},
				{
					EventName: "I hate the Red Sox",
				},
			},
			expectedError: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			// Setup temp file that tracee-rules reads from
			f, err := os.CreateTemp("", "TestSetupTraceeJSONInputSource-")
			if err != nil {
				t.Error(err)
			}
			defer func() {
				_ = f.Close()
				_ = os.RemoveAll(f.Name())
			}()

			allEventBytes := []byte{}
			for _, ev := range testCase.events {
				b, err := json.Marshal(ev)
				if err != nil {
					t.Error(err)
				}
				b = append(b, '\n')
				allEventBytes = append(allEventBytes, b...)
			}
			err = os.WriteFile(f.Name(), allEventBytes, 0644)
			if err != nil {
				t.Error(err)
			}

			// Set up reading from the file
			opts := &traceeInputOptions{inputFile: f, inputFormat: jsonInputFormat}
			eventsChan, err := setupTraceeJSONInputSource(opts)
			assert.Equal(t, testCase.expectedError, err)

			readEvents := []trace.Event{}

			for e := range eventsChan {
				traceeEvt, ok := e.Payload.(trace.Event)
				require.True(t, ok)
				readEvents = append(readEvents, traceeEvt)
			}

			assert.Equal(t, testCase.events, readEvents)
		})
	}
}
