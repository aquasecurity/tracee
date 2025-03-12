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
			logOptions: []string{"level=debug"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=info"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=warn"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=error"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=fatal"},
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
			logOptions: []string{"aggregate.enabled=true"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate.flush-interval=10s"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate.flush-interval=2m"},
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
			logOptions: []string{"level=debug", "aggregate.enabled=true"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"level=debug", "aggregate.flush-interval=10s"},
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

		// valid exclude filter options
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.file=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.lvl=info"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.libbpf"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid exclude filter options
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude."},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.exclude.", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude.invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.exclude.invalid", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude.msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.exclude.msg", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude.msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter.exclude.msg=", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude.regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter.exclude.regex=[whatever", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filter.exclude.lvl=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter.exclude.lvl=invalid", false),
		},

		// valid filter options
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.file=whatever"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.lvl=info"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.libbpf"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid filter options
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include."},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include.invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.invalid", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include.msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.msg", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include.msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.msg=", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include.regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.regex=[whatever", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filter.include.lvl=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter.include.lvl=invalid", false),
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
