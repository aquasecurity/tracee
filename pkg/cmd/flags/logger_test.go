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
			logOptions: []string{"filters.exclude.msg=whatever"},
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
			logOptions: []string{"filters.exclude.regex=^whatever$"},
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
			logOptions: []string{"filters.exclude.pkg=whatever"},
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
			logOptions: []string{"filters.exclude.file=whatever"},
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
			logOptions: []string{"filters.exclude.level=info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "level", "info", logger.FilterOut),
			},
			expectedError: nil,
		},
		{
			testName:   "valid exclude filter option",
			logOptions: []string{"filters.exclude.libbpf"},
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
			logOptions:     []string{"filters.exclude."},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.exclude.", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filters.exclude.invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.exclude.invalid", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filters.exclude.msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.exclude.msg", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filters.exclude.msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filters.exclude.msg=", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filters.exclude.regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filters.exclude.regex=[whatever", false),
		},
		{
			testName:       "invalid exclude filter option",
			logOptions:     []string{"filters.exclude.level=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filters.exclude.level=invalid", false),
		},
		// valid include filter options
		{
			testName:   "valid filter option",
			logOptions: []string{"filters.include.msg=whatever"},
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
			logOptions: []string{"filters.include.regex=^whatever$"},
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
			logOptions: []string{"filters.include.pkg=whatever"},
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
			logOptions: []string{"filters.include.file=whatever"},
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
			logOptions: []string{"filters.include.level=info"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter:        createExpectedFilter(t, "level", "info", logger.FilterIn),
			},
			expectedError: nil,
		},
		{
			testName:   "valid filter option",
			logOptions: []string{"filters.include.libbpf"},
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
			logOptions:     []string{"filters.include"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include."},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include.", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include.invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include.invalid", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include.msg"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include.msg", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include.msg="},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include.msg=", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include.regex=[whatever"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOption(nil, "filters.include.regex=[whatever", false),
		},
		{
			testName:       "invalid filter option",
			logOptions:     []string{"filters.include.level=invalid"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  invalidLogOptionValue(nil, "filters.include.level=invalid", false),
		},
		{
			testName:   "filter with multiple values",
			logOptions: []string{"filters.include.msg=error,warning,info"},
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
			logOptions: []string{"filters.include.pkg=core,ebpf,logger"},
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
			logOptions: []string{"filters.include.file=logger.go,flags.go,main.go"},
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
			logOptions: []string{"filters.include.regex=^error,^warn,^debug"},
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
			logOptions: []string{"filters.include.msg=error", "filters.include.pkg=core", "filters.exclude.level=debug"},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter: createExpectedMultiFilter(t, []filterTest{
					{"msg", "error", logger.FilterIn},
					{"pkg", "core", logger.FilterIn},
					{"level", "debug", logger.FilterOut},
				}),
			},
			expectedError: nil,
		},
		{
			testName: "comprehensive filter options",
			logOptions: []string{
				"filters.include.msg=error,warning",
				"filters.include.pkg=core,ebpf",
				"filters.include.level=info,warn",
				"filters.include.regex=^debug,^trace",
				"filters.include.libbpf",
				"filters.exclude.msg=spam,noise",
				"filters.exclude.pkg=test,example",
				"filters.exclude.level=debug",
				"filters.exclude.regex=^verbose,^debug",
			},
			expectedReturn: logger.LoggingConfig{
				LoggerConfig: logger.LoggerConfig{
					Level: logger.NewAtomicLevelAt(logger.DefaultLevel),
				},
				FlushInterval: logger.DefaultFlushInterval,
				Filter: createExpectedMultiFilter(t, []filterTest{
					// Include filters
					{"msg", "error,warning", logger.FilterIn},
					{"pkg", "core,ebpf", logger.FilterIn},
					{"level", "info,warn", logger.FilterIn},
					{"regex", "^debug,^trace", logger.FilterIn},
					{"regex", "^libbpf:", logger.FilterIn}, // libbpf creates a regex filter
					// Exclude filters
					{"msg", "spam,noise", logger.FilterOut},
					{"pkg", "test,example", logger.FilterOut},
					{"level", "debug", logger.FilterOut},
					{"regex", "^verbose,^debug", logger.FilterOut},
				}),
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
		if strings.HasPrefix(option, "filters.") {
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
	case "level":
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
		case "level":
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
