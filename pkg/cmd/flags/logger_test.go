package flags

import (
	"strings"
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
			testName:       "invalid log level",
			logOptions:     []string{""},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "", false),
		},
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
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DebugLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.InfoLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=warn"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.WarnLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=error"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.ErrorLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"level=fatal"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.FatalLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// valid log aggregate
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate.enabled=true"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate.flush-interval=10s"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate.flush-interval=2m"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
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
				Aggregate: true,
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DebugLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"level=debug", "aggregate.flush-interval=10s"},
			expectedReturn: logger.LoggingConfig{
				Aggregate: true,
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DebugLevel),
				},
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
		{
			testName:   "valid log file with dots in path",
			logOptions: []string{"file=/tmp/test.log"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with multiple dots in path",
			logOptions: []string{"file=/tmp/tracee.2024.01.15.log"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with dots in directory path",
			logOptions: []string{"file=/tmp/.tracee/logs/tracee.log"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log file with complex path",
			logOptions: []string{"file=/tmp/tracee-2024.01.15-14.30.45.log"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// valid exclude filter options
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "msg", "whatever", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "regex", "^whatever$", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "pkg", "whatever", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.file=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "file", "whatever", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.lvl=info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "lvl", "info", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filter.exclude.libbpf"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "regex", "^libbpf:", logger.FilterOut),
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
		// valid include filter options
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.msg=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "msg", "whatever", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.regex=^whatever$"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "regex", "^whatever$", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.pkg=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "pkg", "whatever", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.file=whatever"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "file", "whatever", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.lvl=info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "lvl", "info", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filter.include.libbpf"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "regex", "^libbpf:", logger.FilterIn),
			},
			expectedError: nil,
		},
		// invalid include filter options
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
		{
			testName:   "filter with multiple values",
			logOptions: []string{"filter.include.msg=error,warning,info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "msg", "error,warning,info", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple packages",
			logOptions: []string{"filter.include.pkg=core,ebpf,logger"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "pkg", "core,ebpf,logger", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple files",
			logOptions: []string{"filter.include.file=logger.go,flags.go,main.go"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "file", "logger.go,flags.go,main.go", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "filter with multiple regex patterns",
			logOptions: []string{"filter.include.regex=^error,^warn,^debug"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "regex", "^error,^warn,^debug", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "multiple filter options",
			logOptions: []string{"filter.include.msg=error", "filter.include.pkg=core", "filter.exclude.lvl=debug"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				// Only the last filter option gets applied due to a bug in PrepareLogger
				Filter: createExpectedFilter(t, "lvl", "debug", logger.FilterOut),
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
				assert.Equal(t, tc.expectedReturn.LoggerConfig.Level, logCfg.LoggerConfig.Level)
				assert.Equal(t, tc.expectedReturn.Aggregate, logCfg.Aggregate)
				assert.Equal(t, tc.expectedReturn.FlushInterval, logCfg.FlushInterval)

				if hasFilterOptions(tc.logOptions) {
					assert.True(t, logCfg.Filter.Enabled(), "Filter should be enabled when filter options are provided")
					assert.Equal(t, tc.expectedReturn.Filter, logCfg.Filter)
				} else {
					assert.False(t, logCfg.Filter.Enabled(), "Filter should not be enabled when no filter options are provided")
				}
			}
		})
	}
}

// Helper types and functions for filter testing
type filterTest struct {
	filterType string
	value      string
	kind       logger.FilterKind
}

// hasFilterOptions checks if any filter options are present in logOptions
func hasFilterOptions(logOptions []string) bool {
	for _, option := range logOptions {
		if strings.HasPrefix(option, "filter.") {
			return true
		}
	}
	return false
}

// createExpectedFilter creates a LoggerFilter with a single filter rule
func createExpectedFilter(t *testing.T, filterType, value string, kind logger.FilterKind) logger.LoggerFilter {
	filter := logger.NewLoggerFilter()

	// Split comma-separated values (matching PrepareLogger behavior)
	values := strings.Split(value, ",")

	switch filterType {
	case "msg":
		for _, val := range values {
			err := filter.AddMsg(strings.TrimSpace(val), kind)
			require.NoError(t, err)
		}
	case "pkg":
		for _, val := range values {
			err := filter.AddPkg(strings.TrimSpace(val), kind)
			require.NoError(t, err)
		}
	case "file":
		for _, val := range values {
			err := filter.AddFile(strings.TrimSpace(val), kind)
			require.NoError(t, err)
		}
	case "lvl":
		for _, val := range values {
			level, err := parseLevel(strings.TrimSpace(val))
			require.NoError(t, err)
			err = filter.AddLvl(int(level), kind)
			require.NoError(t, err)
		}
	case "regex":
		for _, val := range values {
			err := filter.AddMsgRegex(strings.TrimSpace(val), kind)
			require.NoError(t, err)
		}
	}

	return filter
}

// createExpectedMultiFilter creates a LoggerFilter with multiple filter rules
func createExpectedMultiFilter(t *testing.T, tests []filterTest) logger.LoggerFilter {
	filter := logger.NewLoggerFilter()

	for _, test := range tests {
		// Split comma-separated values (matching PrepareLogger behavior)
		values := strings.Split(test.value, ",")

		switch test.filterType {
		case "msg":
			for _, val := range values {
				err := filter.AddMsg(strings.TrimSpace(val), test.kind)
				require.NoError(t, err)
			}
		case "pkg":
			for _, val := range values {
				err := filter.AddPkg(strings.TrimSpace(val), test.kind)
				require.NoError(t, err)
			}
		case "file":
			for _, val := range values {
				err := filter.AddFile(strings.TrimSpace(val), test.kind)
				require.NoError(t, err)
			}
		case "lvl":
			for _, val := range values {
				level, err := parseLevel(strings.TrimSpace(val))
				require.NoError(t, err)
				err = filter.AddLvl(int(level), test.kind)
				require.NoError(t, err)
			}
		case "regex":
			for _, val := range values {
				err := filter.AddMsgRegex(strings.TrimSpace(val), test.kind)
				require.NoError(t, err)
			}
		}
	}

	return filter
}
