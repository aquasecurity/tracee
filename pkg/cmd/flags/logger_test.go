package flags

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/logger"
)

func TestPrepareLogger(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		logOptions     []string
		expectedReturn logger.LoggingConfig
		expectedError  error
	}{
		// invalid log option
		{
			testName:       "invalid log option",
			logOptions:     []string{"invalid-option"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "invalid-option", false),
		},
		// valid log level
		{
			testName:   "valid log level",
			logOptions: []string{"debug"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"info"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"warn"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"error"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"fatal"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid log level
		{
			testName:       "invalid log level",
			logOptions:     []string{"invalid-level"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "invalid-level", false),
		},
		{
			testName:       "invalid log level",
			logOptions:     []string{""},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "", false),
		},

		// valid log aggregate
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate:10s"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate:2m"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 2 * time.Minute,
			},
			expectedError: nil,
		},
		// invalid log aggregate
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:", false),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:s"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:s", false),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:-1"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:-1", false),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:abc"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:abc", false),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:15"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:15", false),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:1ms"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate:1ms", false),
		},

		// valid log level + aggregate
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"debug", "aggregate"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"debug", "aggregate:10s"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:       "invalid log file",
			logOptions:     []string{"file:"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "file:", false),
		},

		// valid filter-out options
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:file=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:lvl=info"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter-out option",
			logOptions: []string{"filter-out:libbpf"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid filter-out options
		{
			testName:       "invalid filter-out option",
			logOptions:     []string{"filter-out:"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter-out:", false),
		},
		{
			testName:       "invalid filter-out option",
			logOptions:     []string{"filter-out:invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter-out:invalid", false),
		},
		{
			testName:       "invalid filter-out option",
			logOptions:     []string{"filter-out:msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter-out:msg", false),
		},
		{
			testName:       "invalid filter-out option",
			logOptions:     []string{"filter-out:msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter-out:msg=", false),
		},
		{
			testName:       "invalid filter-out option",
			logOptions:     []string{"filter-out:regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter-out:regex=[whatever", false),
		},
		{
			testName:       "valid filter-out option",
			logOptions:     []string{"filter-out:lvl=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter-out:lvl=invalid", false),
		},

		// valid filter options
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:file=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:lvl=info"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter:libbpf"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid filter options
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter:"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter:", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter:invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter:invalid", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter:msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter:msg", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter:msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter:msg=", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter:regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter:regex=[whatever", false),
		},
		{
			testName:       "valid filter option",
			logOptions:     []string{"filter:lvl=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter:lvl=invalid", false),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			logCfg, err := PrepareLogger(tc.logOptions, false)
			if tc.expectedError != nil {
				require.Equal(t, logger.LoggingConfig{}, logCfg)
				require.Error(t, err)
				// TODO: use error vars to make possible to compare errors
				// assert.ErrorContains(t, err, tc.expectedError.Error())
			}
			if tc.expectedError == nil {
				require.Nil(t, err)
				require.NotNil(t, logCfg)
				assert.Equal(t, tc.expectedReturn.Aggregate, logCfg.Aggregate)
				assert.Equal(t, tc.expectedReturn.FlushInterval, logCfg.FlushInterval)
			}
		})
	}
}
