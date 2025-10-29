package flags

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/logger"
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
		// valid log file with dots in path (regression test for parsing bug)
		{
			testName:   "valid log file with dots in path",
			logOptions: []string{"file=/tmp/test.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with multiple dots in path",
			logOptions: []string{"file=/tmp/tracee.2024.01.15.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with dots in directory path",
			logOptions: []string{"file=/tmp/.tracee/logs/tracee.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with complex path",
			logOptions: []string{"file=/tmp/tracee-2024.01.15-14.30.45.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
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

		// Additional comprehensive test cases
		{
			testName:   "multiple log options combined",
			logOptions: []string{"level=debug", "file=/tmp/test.log", "aggregate.enabled=true"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "aggregate with custom flush interval",
			logOptions: []string{"aggregate.flush-interval=10s"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:   "aggregate with minutes flush interval",
			logOptions: []string{"aggregate.flush-interval=2m"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: 2 * time.Minute,
			},
			expectedError: nil,
		},
		{
			testName:       "invalid aggregate option",
			logOptions:     []string{"aggregate.invalid=value"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "aggregate.invalid=value", false),
		},
		{
			testName:       "invalid aggregate enabled value",
			logOptions:     []string{"aggregate.enabled=maybe"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate.enabled=maybe", false),
		},
		{
			testName:       "invalid aggregate flush interval format",
			logOptions:     []string{"aggregate.flush-interval=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate.flush-interval=invalid", false),
		},
		{
			testName:       "invalid aggregate flush interval suffix",
			logOptions:     []string{"aggregate.flush-interval=5h"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate.flush-interval=5h", false),
		},
		{
			testName:       "invalid aggregate flush interval empty",
			logOptions:     []string{"aggregate.flush-interval="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "aggregate.flush-interval=", false),
		},
		{
			testName:   "filter with multiple values",
			logOptions: []string{"filter.include.msg=error,warning,info"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple packages",
			logOptions: []string{"filter.include.pkg=core,ebpf,logger"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple files",
			logOptions: []string{"filter.include.file=logger.go,flags.go,main.go"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple levels",
			logOptions: []string{"filter.include.lvl=error,warn"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple regex patterns",
			logOptions: []string{"filter.include.regex=^error,^warn,^debug"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "multiple filter options",
			logOptions: []string{"filter.include.msg=error", "filter.include.pkg=core", "filter.exclude.lvl=debug"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "complex file path with multiple dots",
			logOptions: []string{"file=/tmp/tracee.2024.01.15-14.30.45.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "file path with dots in directory",
			logOptions: []string{"file=/tmp/.tracee/logs/tracee.log"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "empty log options",
			logOptions: []string{},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:       "invalid filter type",
			logOptions:     []string{"filter.include.invalidtype=value"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter.include.invalidtype=value", false),
		},
		{
			testName:       "invalid filter direction",
			logOptions:     []string{"filter.invalid.msg=value"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filter.invalid.msg=value", false),
		},
		{
			testName:       "malformed filter option",
			logOptions:     []string{"filter"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filter", false),
		},
		{
			testName:       "malformed aggregate option",
			logOptions:     []string{"aggregate"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "aggregate", false),
		},
		{
			testName:       "empty level value",
			logOptions:     []string{"level="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "level=", false),
		},
		{
			testName:       "empty file value",
			logOptions:     []string{"file="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "file=", false),
		},
		{
			testName:   "aggregate enabled false",
			logOptions: []string{"aggregate.enabled=false"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "filter exclude libbpf",
			logOptions: []string{"filter.exclude.libbpf"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "all log levels",
			logOptions: []string{"level=fatal"},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:       "invalid log level case",
			logOptions:     []string{"level=DEBUG"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "level=DEBUG", false),
		},
		{
			testName:       "invalid log level number",
			logOptions:     []string{"level=5"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "level=5", false),
		},
		{
			testName:   "edge case: single character file path",
			logOptions: []string{"file=a"},
			expectedReturn: logger.LoggingConfig{
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:       "edge case: empty file path",
			logOptions:     []string{"file="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "file=", false),
		},
		{
			testName: "comprehensive example",
			logOptions: []string{
				"level=debug",
				"file=/tmp/tracee.log",
				"aggregate.enabled=true",
				"filter.include.msg=error,warning",
				"filter.include.pkg=core",
				"filter.exclude.lvl=debug",
				"filter.exclude.file=test.go",
			},
			expectedReturn: logger.LoggingConfig{
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
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
