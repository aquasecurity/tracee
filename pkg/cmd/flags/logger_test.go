package flags_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func TestPrepareLogger(t *testing.T) {
	testCases := []struct {
		testName       string
		logOptions     []string
		expectedReturn *logger.LoggerConfig
		expectedError  error
	}{
		// valid log level
		{
			testName:   "valid log level",
			logOptions: []string{"debug"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DebugLevel,
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"info"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.InfoLevel,
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"warn"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.WarnLevel,
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"error"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.ErrorLevel,
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level",
			logOptions: []string{"fatal"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.FatalLevel,
				Aggregate:     false,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		// invalid log level
		{
			testName:       "invalid log level",
			logOptions:     []string{"invalid-level"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("invalid-level"),
		},
		{
			testName:       "invalid log level",
			logOptions:     []string{""},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption(""),
		},

		// valid log aggregate
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DefaultLevel,
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate:10s"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DefaultLevel,
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log aggregate",
			logOptions: []string{"aggregate:2m"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DefaultLevel,
				Aggregate:     true,
				FlushInterval: 2 * time.Minute,
			},
			expectedError: nil,
		},
		// invalid log aggregate
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"invalid-aggregate"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("invalid-aggregate"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:s"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:s"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:-1"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:-1"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:abc"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:abc"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:15"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:15"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:1ms"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("aggregate:1ms"),
		},

		// valid log level + aggregate
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"debug", "aggregate"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DebugLevel,
				Aggregate:     true,
				FlushInterval: logger.DefaultFlushInterval,
			},
			expectedError: nil,
		},
		{
			testName:   "valid log level + aggregate",
			logOptions: []string{"debug", "aggregate:10s"},
			expectedReturn: &logger.LoggerConfig{
				Level:         logger.DebugLevel,
				Aggregate:     true,
				FlushInterval: 10 * time.Second,
			},
			expectedError: nil,
		},
		{
			testName:       "invalid log file",
			logOptions:     []string{"file:"},
			expectedReturn: nil,
			expectedError:  flags.InvalidLogOption("file:"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			logCfg, err := flags.PrepareLogger(tc.logOptions)
			if tc.expectedError != nil {
				require.Nil(t, logCfg)
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedError.Error())
			}
			if tc.expectedError == nil {
				require.Nil(t, err)
				require.NotNil(t, logCfg)
				assert.Equal(t, tc.expectedReturn.Level, logCfg.Level)
				assert.Equal(t, tc.expectedReturn.Aggregate, logCfg.Aggregate)
				assert.Equal(t, tc.expectedReturn.FlushInterval, logCfg.FlushInterval)
			}
		})
	}
}
