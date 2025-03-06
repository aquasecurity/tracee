package flags

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/common/logger"
)

func TestLogConfig_flags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   LogConfig
		expected []string
	}{
		{
			name: "empty config",
			config: LogConfig{
				Level: "",
				File:  "",
			},
			expected: []string{},
		},
		{
			name: "level only",
			config: LogConfig{
				Level: "debug",
			},
			expected: []string{
				"level=debug",
			},
		},
		{
			name: "file only",
			config: LogConfig{
				File: "/var/log/test.log",
			},
			expected: []string{
				"file=/var/log/test.log",
			},
		},
		{
			name: "aggregate only",
			config: LogConfig{
				Aggregate: LogAggregateConfig{
					Enabled:       true,
					FlushInterval: "",
				},
			},
			expected: []string{
				"aggregate",
			},
		},
		{
			name: "aggregate with interval",
			config: LogConfig{
				Aggregate: LogAggregateConfig{
					Enabled:       true,
					FlushInterval: "5s",
				},
			},
			expected: []string{
				"aggregate",
				"aggregate.flush-interval=5s",
			},
		},
		{
			name: "filters with libbpf",
			config: LogConfig{
				Filters: LogFilterConfig{
					Include: LogFilterAttributes{
						LibBPF: true,
					},
				},
			},
			expected: []string{
				"filters.include.libbpf",
			},
		},
		{
			name: "filters with attributes",
			config: LogConfig{
				Filters: LogFilterConfig{
					Include: LogFilterAttributes{
						Msg: []string{
							"msg1",
							"msg2",
						},
						Pkg: []string{
							"pkg1",
						},
						File: []string{
							"file1",
							"file2",
						},
						Level: []string{
							"lvl1",
						},
						Regex: []string{
							"^test.*",
						},
					},
				},
			},
			expected: []string{
				"filters.include.msg=msg1",
				"filters.include.msg=msg2",
				"filters.include.pkg=pkg1",
				"filters.include.file=file1",
				"filters.include.file=file2",
				"filters.include.level=lvl1",
				"filters.include.regex=^test.*",
			},
		},
		{
			name: "all flags",
			config: LogConfig{
				Level: "debug",
				File:  "/var/log/test.log",
				Aggregate: LogAggregateConfig{
					FlushInterval: "10s",
					Enabled:       true,
				},
				Filters: LogFilterConfig{
					Include: LogFilterAttributes{
						Msg:    []string{"msg1"},
						Pkg:    []string{"pkg1", "pkg2"},
						File:   []string{"file1"},
						Level:  []string{"lvl1", "lvl2"},
						Regex:  []string{"^regex.*"},
						LibBPF: true,
					},
					Exclude: LogFilterAttributes{
						Msg:   []string{"msg1"},
						Pkg:   []string{"pkg1"},
						File:  []string{"file1", "file2"},
						Level: []string{"lvl1"},
						Regex: []string{"^regex.*"},
					},
				},
			},
			expected: []string{
				"level=debug",
				"file=/var/log/test.log",
				"aggregate.flush-interval=10s",
				"aggregate",
				"filters.include.libbpf",
				"filters.include.msg=msg1",
				"filters.include.pkg=pkg1",
				"filters.include.pkg=pkg2",
				"filters.include.file=file1",
				"filters.include.level=lvl1",
				"filters.include.level=lvl2",
				"filters.include.regex=^regex.*",
				"filters.exclude.msg=msg1",
				"filters.exclude.pkg=pkg1",
				"filters.exclude.file=file1",
				"filters.exclude.file=file2",
				"filters.exclude.level=lvl1",
				"filters.exclude.regex=^regex.*",
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.flags()

			if !slicesEqualIgnoreOrder(got, tt.expected) {
				t.Errorf("flags() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPrepareLogger(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		logOptions     []string
		expectedLevel  logger.Level
		expectedAgg    bool
		expectedFlush  time.Duration
		expectedFilter logger.LoggerFilter
		expectedError  error
	}{
		// invalid log option
		{
			testName:      "invalid log level",
			logOptions:    []string{""},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, ""),
		},
		{
			testName:      "invalid log option",
			logOptions:    []string{"invalid-option"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "invalid-option"),
		},
		// valid log level
		{
			testName:      "valid log level debug",
			logOptions:    []string{"level=debug"},
			expectedLevel: logger.DebugLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log level info",
			logOptions:    []string{"level=info"},
			expectedLevel: logger.InfoLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log level warn",
			logOptions:    []string{"level=warn"},
			expectedLevel: logger.WarnLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log level error",
			logOptions:    []string{"level=error"},
			expectedLevel: logger.ErrorLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log level fatal",
			logOptions:    []string{"level=fatal"},
			expectedLevel: logger.FatalLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		// valid log aggregate
		{
			testName:      "valid log aggregate enabled",
			logOptions:    []string{"aggregate"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   true,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log aggregate flush-interval",
			logOptions:    []string{"aggregate.flush-interval=10s"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   true,
			expectedFlush: 10 * time.Second,
			expectedError: nil,
		},
		{
			testName:      "valid log aggregate flush-interval minutes",
			logOptions:    []string{"aggregate.flush-interval=2m"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   true,
			expectedFlush: 2 * time.Minute,
			expectedError: nil,
		},
		// invalid log aggregate
		{
			testName:      "invalid log aggregate missing dot",
			logOptions:    []string{"aggregate:"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "aggregate:"),
		},
		{
			testName:      "invalid log aggregate invalid format",
			logOptions:    []string{"aggregate.s"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "aggregate.s"),
		},
		{
			testName:      "invalid log aggregate invalid value",
			logOptions:    []string{"aggregate.flush-interval=-1"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "aggregate.flush-interval=-1"),
		},
		{
			testName:      "invalid log aggregate invalid value",
			logOptions:    []string{"aggregate.flush-interval=abc"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "aggregate.flush-interval=abc"),
		},
		{
			testName:      "invalid log aggregate no suffix",
			logOptions:    []string{"aggregate.flush-interval=15"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "aggregate.flush-interval=15"),
		},
		{
			testName:      "invalid log aggregate milliseconds not allowed",
			logOptions:    []string{"aggregate.flush-interval=1ms"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "aggregate.flush-interval=1ms"),
		},
		// valid log level + aggregate
		{
			testName:      "valid log level + aggregate",
			logOptions:    []string{"level=debug", "aggregate"},
			expectedLevel: logger.DebugLevel,
			expectedAgg:   true,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log level + aggregate flush",
			logOptions:    []string{"level=debug", "aggregate", "aggregate.flush-interval=10s"},
			expectedLevel: logger.DebugLevel,
			expectedAgg:   true,
			expectedFlush: 10 * time.Second,
			expectedError: nil,
		},
		// invalid log file
		{
			testName:      "invalid log file empty",
			logOptions:    []string{"file="},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "file="),
		},
		// valid log file
		{
			testName:      "valid log file",
			logOptions:    []string{"file=/tmp/test.log"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log file with multiple dots",
			logOptions:    []string{"file=/tmp/tracee.2024.01.15.log"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log file with dots in directory",
			logOptions:    []string{"file=/tmp/.tracee/logs/tracee.log"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		{
			testName:      "valid log file complex path",
			logOptions:    []string{"file=/tmp/tracee-2024.01.15-14.30.45.log"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedError: nil,
		},
		// valid exclude filter options
		{
			testName:       "valid exclude filter msg",
			logOptions:     []string{"filters.exclude.msg=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "msg", "whatever", logger.FilterOut),
			expectedError:  nil,
		},
		{
			testName:       "valid exclude filter regex",
			logOptions:     []string{"filters.exclude.regex=^whatever$"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "regex", "^whatever$", logger.FilterOut),
			expectedError:  nil,
		},
		{
			testName:       "valid exclude filter pkg",
			logOptions:     []string{"filters.exclude.pkg=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "pkg", "whatever", logger.FilterOut),
			expectedError:  nil,
		},
		{
			testName:       "valid exclude filter file",
			logOptions:     []string{"filters.exclude.file=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "file", "whatever", logger.FilterOut),
			expectedError:  nil,
		},
		{
			testName:       "valid exclude filter level",
			logOptions:     []string{"filters.exclude.level=info"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "level", "info", logger.FilterOut),
			expectedError:  nil,
		},
		{
			testName:       "valid exclude filter libbpf",
			logOptions:     []string{"filters.exclude.libbpf"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "regex", "^libbpf:", logger.FilterOut),
			expectedError:  nil,
		},
		// invalid exclude filter options
		{
			testName:      "invalid exclude filter empty",
			logOptions:    []string{"filters.exclude."},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.exclude."),
		},
		{
			testName:      "invalid exclude filter invalid type",
			logOptions:    []string{"filters.exclude.invalid"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.exclude.invalid"),
		},
		{
			testName:      "invalid exclude filter missing value",
			logOptions:    []string{"filters.exclude.msg"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.exclude.msg"),
		},
		{
			testName:      "invalid exclude filter empty value",
			logOptions:    []string{"filters.exclude.msg="},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.exclude.msg="),
		},
		{
			testName:      "invalid exclude filter invalid regex",
			logOptions:    []string{"filters.exclude.regex=[whatever"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.exclude.regex=[whatever"),
		},
		{
			testName:      "invalid exclude filter invalid level",
			logOptions:    []string{"filters.exclude.level=invalid"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.exclude.level=invalid"),
		},
		// valid include filter options
		{
			testName:       "valid include filter msg",
			logOptions:     []string{"filters.include.msg=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "msg", "whatever", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "valid include filter regex",
			logOptions:     []string{"filters.include.regex=^whatever$"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "regex", "^whatever$", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "valid include filter pkg",
			logOptions:     []string{"filters.include.pkg=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "pkg", "whatever", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "valid include filter file",
			logOptions:     []string{"filters.include.file=whatever"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "file", "whatever", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "valid include filter level",
			logOptions:     []string{"filters.include.level=info"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "level", "info", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "valid include filter libbpf",
			logOptions:     []string{"filters.include.libbpf"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "regex", "^libbpf:", logger.FilterIn),
			expectedError:  nil,
		},
		// invalid include filter options
		{
			testName:      "invalid include filter missing dot",
			logOptions:    []string{"filters.include"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.include"),
		},
		{
			testName:      "invalid include filter empty",
			logOptions:    []string{"filters.include."},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.include."),
		},
		{
			testName:      "invalid include filter invalid type",
			logOptions:    []string{"filters.include.invalid"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.include.invalid"),
		},
		{
			testName:      "invalid include filter missing value",
			logOptions:    []string{"filters.include.msg"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOption(nil, "filters.include.msg"),
		},
		{
			testName:      "invalid include filter empty value",
			logOptions:    []string{"filters.include.msg="},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.include.msg="),
		},
		{
			testName:      "invalid include filter invalid regex",
			logOptions:    []string{"filters.include.regex=[whatever"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.include.regex=[whatever"),
		},
		{
			testName:      "invalid include filter invalid level",
			logOptions:    []string{"filters.include.level=invalid"},
			expectedLevel: logger.DefaultLevel,
			expectedError: invalidLogOptionValue(nil, "filters.include.level=invalid"),
		},
		// filter with multiple values
		{
			testName:       "filter with multiple msg values",
			logOptions:     []string{"filters.include.msg=error,warning,info"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "msg", "error,warning,info", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "filter with multiple pkg values",
			logOptions:     []string{"filters.include.pkg=core,ebpf,logger"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "pkg", "core,ebpf,logger", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "filter with multiple file values",
			logOptions:     []string{"filters.include.file=logger.go,flags.go,main.go"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "file", "logger.go,flags.go,main.go", logger.FilterIn),
			expectedError:  nil,
		},
		{
			testName:       "filter with multiple regex values",
			logOptions:     []string{"filters.include.regex=^error,^warn,^debug"},
			expectedLevel:  logger.DefaultLevel,
			expectedAgg:    false,
			expectedFlush:  logger.DefaultFlushInterval,
			expectedFilter: createExpectedFilter(t, "regex", "^error,^warn,^debug", logger.FilterIn),
			expectedError:  nil,
		},
		// multiple filter options
		{
			testName:      "multiple filter options",
			logOptions:    []string{"filters.include.msg=error", "filters.include.pkg=core", "filters.exclude.level=debug"},
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedFilter: createExpectedMultiFilter(t, []filterTest{
				{"msg", "error", logger.FilterIn},
				{"pkg", "core", logger.FilterIn},
				{"level", "debug", logger.FilterOut},
			}),
			expectedError: nil,
		},
		// comprehensive filter options
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
			expectedLevel: logger.DefaultLevel,
			expectedAgg:   false,
			expectedFlush: logger.DefaultFlushInterval,
			expectedFilter: createExpectedMultiFilter(t, []filterTest{
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
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			logCfg, err := PrepareLogger(tc.logOptions)
			if tc.expectedError != nil {
				require.Equal(t, LogConfig{}, logCfg)
				require.Error(t, err)
				// TODO: use error vars to make possible to compare errors
				// assert.ErrorContains(t, err, tc.expectedError.Error())
				return
			}

			require.NoError(t, err)
			require.NotNil(t, logCfg)

			// Test the parsed configuration by checking GetLoggingConfig result
			// This tests the flags parsing logic, not the logger implementation
			loggingCfg := logCfg.GetLoggingConfig()

			// Verify level parsing
			assert.Equal(t, tc.expectedLevel, loggingCfg.LoggerConfig.Level.Level(), "Level should match parsed value")

			// Verify aggregation parsing
			assert.Equal(t, tc.expectedAgg, loggingCfg.Aggregate, "Aggregate flag should match parsed value")
			assert.Equal(t, tc.expectedFlush, loggingCfg.FlushInterval, "FlushInterval should match parsed value")

			// Verify filter parsing
			if hasFilterOptions(tc.logOptions) {
				assert.True(t, loggingCfg.Filter.Enabled(), "Filter should be enabled when filter options are provided")
				assert.Equal(t, tc.expectedFilter, loggingCfg.Filter, "Filter should match parsed value")
			} else {
				assert.False(t, loggingCfg.Filter.Enabled(), "Filter should not be enabled when no filter options are provided")
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
