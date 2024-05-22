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
			eventFlag: "openat.scope.userId=0",
			expected: []eventFlag{
				{
					full:              "openat.scope.userId=0",
					eventFilter:       "openat.scope.userId",
					eventName:         "openat",
					eventOptionType:   "scope",
					eventOptionName:   "userId",
					operator:          "=",
					values:            "0",
					operatorAndValues: "=0",
					filter:            "scope.userId=0",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat.data.pathname=/etc/*",
			expected: []eventFlag{
				{
					full:              "openat.data.pathname=/etc/*",
					eventFilter:       "openat.data.pathname",
					eventName:         "openat",
					eventOptionType:   "data",
					eventOptionName:   "pathname",
					operator:          "=",
					values:            "/etc/*",
					operatorAndValues: "=/etc/*",
					filter:            "data.pathname=/etc/*",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "openat.data.pathname!=/fo!der/*", // special char (! operator) in value parsed correctly
			expected: []eventFlag{
				{
					full:              "openat.data.pathname!=/fo!der/*",
					eventFilter:       "openat.data.pathname",
					eventName:         "openat",
					eventOptionType:   "data",
					eventOptionName:   "pathname",
					operator:          "!=",
					values:            "/fo!der/*",
					operatorAndValues: "!=/fo!der/*",
					filter:            "data.pathname!=/fo!der/*",
				},
			},
			expectedError: nil,
		},
		{
			name:      "ValidEventFlag",
			eventFlag: "open.scope.container",
			expected: []eventFlag{
				{
					full:              "open.scope.container",
					eventFilter:       "open.scope.container",
					eventName:         "open",
					eventOptionType:   "scope",
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
			eventFlag:     "openat.data.pathname=",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data.pathname="),
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
			eventFlag:     "openat.data.=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data.=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.data.data.=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data.data.=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.data.data.data=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data.data.data=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat. data.data=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat. data.data=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.data .data=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data .data=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.data. data=/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data. data=/etc/*"),
		},
		{
			name:          "InvalidEventFlagFormat",
			eventFlag:     "openat.data.data =/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFilterFlagFormat("openat.data.data =/etc/*"),
		},
		// InvalidFlagOperator
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pathname==/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pathname==/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pathname=!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pathname=!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pathname!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pathname!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pathname!!/etc/*",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pathname!!/etc/*"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pid<<1",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pid<<1"),
		},
		{
			name:          "InvalidFlagOperator",
			eventFlag:     "openat.data.pid>>1",
			expected:      []eventFlag{},
			expectedError: InvalidFlagOperator("openat.data.pid>>1"),
		},
		// InvalidFlagValue
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.data.pathname=v\t",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.data.pathname=v\t"),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.data.pathname=\tv",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.data.pathname=\tv"),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.data.pathname=v ",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.data.pathname=v "),
		},
		{
			name:          "InvalidFlagValue",
			eventFlag:     "openat.data.pathname= v",
			expected:      []eventFlag{},
			expectedError: InvalidFlagValue("openat.data.pathname= v"),
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
			name: "ValidFlags1",
			eventsArr: []string{
				"close,-open",
				"openat.data.pathname=/etc/*",
				"chmod.data.mode=777",
				"execve.data.pathname!=/bin/bash,/bin/sh",
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
							full:              "openat.data.pathname=/etc/*",
							eventFilter:       "openat.data.pathname",
							eventName:         "openat",
							eventOptionType:   "data",
							eventOptionName:   "pathname",
							operator:          "=",
							values:            "/etc/*",
							operatorAndValues: "=/etc/*",
							filter:            "data.pathname=/etc/*",
						},
						{
							full:              "chmod.data.mode=777",
							eventFilter:       "chmod.data.mode",
							eventName:         "chmod",
							eventOptionType:   "data",
							eventOptionName:   "mode",
							operator:          "=",
							values:            "777",
							operatorAndValues: "=777",
							filter:            "data.mode=777",
						},
						{
							full:              "execve.data.pathname!=/bin/bash,/bin/sh",
							eventFilter:       "execve.data.pathname",
							eventName:         "execve",
							eventOptionType:   "data",
							eventOptionName:   "pathname",
							operator:          "!=",
							values:            "/bin/bash,/bin/sh",
							operatorAndValues: "!=/bin/bash,/bin/sh",
							filter:            "data.pathname!=/bin/bash,/bin/sh",
						},
					},
				},
			},
		},
		// keep a single args (deprecated) filter test that shall break on future removal
		{
			name: "ValidFlags2",
			eventsArr: []string{
				"openat.args.pathname=/etc/*",
				"chmod.args.mode=777",
				"execve.args.pathname!=/bin/bash,/bin/sh",
			},
			expected: PolicyEventMap{
				0: policyEvents{
					eventFlags: []eventFlag{
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
