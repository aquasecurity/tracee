package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hasLeadingOrTrailingWhitespace(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input  string
		output bool
	}{
		// valid
		{"", false},
		{"value", false},
		{"value with spaces", false},
		{"value,with,comma", false},

		// invalid
		{"   ", true},
		{"\t\t", true},
		{"   value", true},
		{"\t\tvalue", true},
		{"value   ", true},
		{"value\t\t", true},
		{" value\t", true},
	}

	for _, testCase := range testCases {
		result := hasLeadingOrTrailingWhitespace(testCase.input)
		assert.Equal(t, testCase.output, result, testCase.input)
	}
}

func Test_isFlagOperatorValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input  string
		output bool
	}{
		// valid
		{"=", true},
		{"!=", true},
		{"<", true},
		{"<=", true},
		{">", true},
		{">=", true},

		// invalid
		{"==", false},
		{"=!", false},
		{"!!", false},
		{"!", false},
		{"><", false},
		{"<>", false},
		{">>", false},
		{"<<", false},
		{"like", false},
		{"", false},
	}

	for _, testCase := range testCases {
		result := isFlagOperatorValid(testCase.input)
		assert.Equal(t, testCase.output, result, testCase.input)
	}
}

func Test_getEventFilterParts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		filter        string
		flag          string
		expectedParts filterOptParts
		expectedError error
	}{
		// Valid filters
		{
			name:   "ValidEventFilter_TwoParts",
			filter: "name.option",
			flag:   "",
			expectedParts: filterOptParts{
				name:    "name",
				optType: "option",
			},
			expectedError: nil,
		},
		{
			name:   "ValidEventFilter_ThreeParts",
			filter: "name.option.optname",
			flag:   "",
			expectedParts: filterOptParts{
				name:    "name",
				optType: "option",
				optName: "optname",
			},
			expectedError: nil,
		},

		// Invalid filters
		{
			name:          "InvalidEventFilter_Empty",
			filter:        "",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_OnePart",
			filter:        "events",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_MoreThanThreeParts",
			filter:        "event.option.optname.someotherpart",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},

		{
			name:          "InvalidEventFilter_LeadingWhitespace",
			filter:        " event.option",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_TrailingWhitespace",
			filter:        "event.option ",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_TrailingWhitespace",
			filter:        "event.option.optname ",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_InbetweenWhitespace",
			filter:        "event. option.optname",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
		{
			name:          "InvalidEventFilter_InbetweenWhitespace",
			filter:        "event.option. optname",
			flag:          "flag",
			expectedParts: filterOptParts{},
			expectedError: InvalidFilterFlagFormat("flag"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parts, err := getEventFilterParts(tc.filter, tc.flag)

			if tc.expectedError == nil {
				assert.Nil(t, err)
				assert.Equal(t, tc.expectedParts, parts)
			} else {
				assert.Error(t, err, tc.expectedError.Error())
			}
		})
	}
}
