package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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
			assert.Equal(t, testcase.expectedError, err)
			assert.Equal(t, testcase.expectedResultOptions, opt)
		})
	}
}
