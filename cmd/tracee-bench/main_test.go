package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseQueryResString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		resultString   string
		expectedResult float64
	}{
		{
			resultString:   `{instance="localhost:3366", job="prometheus"} => 4485.236363636363 @[1648131101.208]`,
			expectedResult: 4485.236363636363,
		},
		{
			resultString:   `{instance="localhost:3366", job="prometheus"} => 4544.054545454545 @[1648131106.208]`,
			expectedResult: 4544.054545454545,
		},
	}

	for _, tc := range testCases {
		res, err := parseQueryResString(tc.resultString)
		assert.NoError(t, err)
		assert.Equal(t, tc.expectedResult, res)
	}
}
