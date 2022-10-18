package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_checkIsHelp(t *testing.T) {
	testCases := []struct {
		testName string
		input    []string
		expected bool
	}{
		{"no flag", []string{""}, false},
		{"help flag", []string{"help"}, true},
		{"capture flag", []string{"capture"}, false},
		{"output flag", []string{"output"}, false},
		{"trace flag", []string{"trace"}, false},
		{"multiple flags", []string{"help", "capture"}, false},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			actual := checkIsHelp(testcase.input)
			assert.Equal(t, testcase.expected, actual)
		})
	}
}
