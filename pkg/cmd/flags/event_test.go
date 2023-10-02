package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEventFlag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		eventFlag     string
		expected      []eventFlag
		expectedError error
	}{
		// Valid
		{
			name:      "ValidEventFlag",
			eventFlag: "openat",
			expected: []eventFlag{
				{
					full:              "openat",
					eventFilter:       "",
					eventName:         "openat",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat,close,execve",
			expected: []eventFlag{
				{
					full:              "openat",
					eventFilter:       "",
					eventName:         "openat",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
				{
					full:              "close",
					eventFilter:       "",
					eventName:         "close",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
				{
					full:              "execve",
					eventFilter:       "",
					eventName:         "execve",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "-openat",
			expected: []eventFlag{
				{
					full:              "-openat",
					eventFilter:       "",
					eventName:         "openat",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "-",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "fs,-close,-openat",
			expected: []eventFlag{
				{
					full:              "fs",
					eventFilter:       "",
					eventName:         "fs",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
				{
					full:              "-close",
					eventFilter:       "",
					eventName:         "close",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "-",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
				{
					full:              "-openat",
					eventFilter:       "",
					eventName:         "openat",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "-",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "-openat",
			expected: []eventFlag{
				{
					full:              "-openat",
					eventFilter:       "",
					eventName:         "openat",
					eventOptionType:   "",
					eventOptionName:   "",
					operator:          "-",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat.context.userId=0",
			expected: []eventFlag{
				{
					full:              "openat.context.userId=0",
					eventFilter:       "openat.context.userId",
					eventName:         "openat",
					eventOptionType:   "context",
					eventOptionName:   "userId",
					operator:          "=",
					values:            "0",
					operatorAndValues: "=0",
					filter:            "context.userId=0",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat.args.pathname=/etc/*",
			expected: []eventFlag{
				{
					full:              "openat.args.pathname=/etc/*",
					eventFilter:       "openat.args.pathname",
					eventName:         "openat",
					eventOptionType:   "args",
					eventOptionName:   "pathname",
					operator:          "=",
					values:            "/etc/*",
					operatorAndValues: "=/etc/*",
					filter:            "args.pathname=/etc/*",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat.args.pathname!=/fo!der/*", // special char (! operator) in value parsed correctly
			expected: []eventFlag{
				{
					full:              "openat.args.pathname!=/fo!der/*",
					eventFilter:       "openat.args.pathname",
					eventName:         "openat",
					eventOptionType:   "args",
					eventOptionName:   "pathname",
					operator:          "!=",
					values:            "/fo!der/*",
					operatorAndValues: "!=/fo!der/*",
					filter:            "args.pathname!=/fo!der/*",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "open.context.container",
			expected: []eventFlag{
				{
					full:              "open.context.container",
					eventFilter:       "open.context.container",
					eventName:         "open",
					eventOptionType:   "context",
					eventOptionName:   "container",
					operator:          "",
					values:            "",
					operatorAndValues: "",
					filter:            "",
				},
			},
			expectedError: nil,
		},

		// Invalid
		// InvalidFlagEmpty
		{
			name:          "InvalidFlagEmpty",
			eventFlag:     "",
			expected:      []eventFlag{},
			expectedError: InvalidFlagEmpty(),
		},
		// InvalidFilterFlagFormat
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat,",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat,"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat,,close",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat,,close"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat ",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat "),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     " openat",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat(" openat"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat\t",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat\t"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "\topenat",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("\topenat"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat=",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat="),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat!=",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat!="),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args.pathname=",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args.pathname="),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args.=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args.=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args.args.=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args.args.=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args.args.args=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args.args.args=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat. args.args=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat. args.args=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args .args=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args .args=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args. args=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args. args=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.args.args =/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.args.args =/etc/*"),
		},
		// InvalidFlagOperator
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pathname==/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pathname==/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pathname=!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pathname=!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pathname!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pathname!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pathname!!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pathname!!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pid<<1",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pid<<1"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.args.pid>>1",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.args.pid>>1"),
		},
		// InvalidFlagValue
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.args.pathname=v\t",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.args.pathname=v\t"),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.args.pathname=\tv",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.args.pathname=\tv"),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.args.pathname=v ",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.args.pathname=v "),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.args.pathname= v",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.args.pathname= v"),
		},
	}

	for _, tt := range testCases {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsedEventFlag, err := parseEventFlag(tt.eventFlag)
			if err != nil {
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.Equal(t, tt.expected, parsedEventFlag)
			}
		})
	}
}

func TestPrepareEventMapFromFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		eventsArr []string
		expected  PolicyEventMap
	}{
		{
			name: "ValidFlags",
			eventsArr: []string{
				"close,-open",
				"openat.args.pathname=/etc/*",
				"chmod.args.mode=777",
				"execve.args.pathname!=/bin/bash,/bin/sh",
			},
			expected: PolicyEventMap{
				0: policyEvents{
					eventFlags: []eventFlag{
						{
							full:              "close",
							eventFilter:       "",
							eventName:         "close",
							eventOptionType:   "",
							eventOptionName:   "",
							operator:          "",
							values:            "",
							operatorAndValues: "",
							filter:            "",
						},
						{
							full:              "-open",
							eventFilter:       "",
							eventName:         "open",
							eventOptionType:   "",
							eventOptionName:   "",
							operator:          "-",
							values:            "",
							operatorAndValues: "",
							filter:            "",
						},
						{
							full:              "openat.args.pathname=/etc/*",
							eventFilter:       "openat.args.pathname",
							eventName:         "openat",
							eventOptionType:   "args",
							eventOptionName:   "pathname",
							operator:          "=",
							values:            "/etc/*",
							operatorAndValues: "=/etc/*",
							filter:            "args.pathname=/etc/*",
						},
						{
							full:              "chmod.args.mode=777",
							eventFilter:       "chmod.args.mode",
							eventName:         "chmod",
							eventOptionType:   "args",
							eventOptionName:   "mode",
							operator:          "=",
							values:            "777",
							operatorAndValues: "=777",
							filter:            "args.mode=777",
						},
						{
							full:              "execve.args.pathname!=/bin/bash,/bin/sh",
							eventFilter:       "execve.args.pathname",
							eventName:         "execve",
							eventOptionType:   "args",
							eventOptionName:   "pathname",
							operator:          "!=",
							values:            "/bin/bash,/bin/sh",
							operatorAndValues: "!=/bin/bash,/bin/sh",
							filter:            "args.pathname!=/bin/bash,/bin/sh",
						},
					},
				},
			},
		},
		{
			name:      "EmptyFlags",
			eventsArr: []string{},
			expected: PolicyEventMap{
				0: policyEvents{
					eventFlags: nil,
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			eventMap, err := PrepareEventMapFromFlags(tc.eventsArr)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, eventMap)
		})
	}
}
