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
		expectedReturn logger.LoggingConfig
		expectedError  error
	}{
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
			expectedError:  flags.InvalidLogOption("invalid-level"),
		},
		{
			testName:       "invalid log level",
			logOptions:     []string{""},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption(""),
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
			logOptions:     []string{"invalid-aggregate"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("invalid-aggregate"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:s"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:s"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:-1"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:-1"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:abc"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:abc"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:15"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:15"),
		},
		{
			testName:       "invalid log aggregate",
			logOptions:     []string{"aggregate:1ms"},
			expectedReturn: logger.LoggingConfig{},
			expectedError:  flags.InvalidLogOption("aggregate:1ms"),
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
			expectedError:  flags.InvalidLogOption("file:"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			logCfg, err := flags.PrepareLogger(tc.logOptions)
			if tc.expectedError != nil {
				require.Equal(t, logger.LoggingConfig{}, logCfg)
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedError.Error())
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
