package logger

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type testBuffer struct {
	bytes.Buffer
}

func (b *testBuffer) Sync() error {
	return nil
}

func newTestLogger() (*Logger, *testBuffer) {
	buf := &testBuffer{}
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:    "msg",
		LevelKey:      "level",
		TimeKey:       "time",
		NameKey:       "logger",
		CallerKey:     "caller",
		StacktraceKey: "stacktrace",
		EncodeLevel:   zapcore.LowercaseLevelEncoder,
		EncodeTime:    zapcore.ISO8601TimeEncoder,
		EncodeCaller:  zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		buf,
		zap.DebugLevel,
	)

	logger := zap.New(core).Sugar()
	return &Logger{
		l: logger,
		cfg: LoggingConfig{
			Logger:        logger,
			Level:         DebugLevel,
			Aggregate:     false,
			FlushInterval: time.Second,
		},
	}, buf
}

func TestLogger_Levels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		logFunc  func(l *Logger, msg string, args ...interface{})
		level    string
		message  string
		keyVals  []interface{}
		expected []string
	}{
		{
			name:    "debug level",
			logFunc: (*Logger).Debugw,
			level:   "debug",
			message: "debug message",
			keyVals: []interface{}{"key1", "value1", "key2", 42},
			expected: []string{
				"debug message",
				"\"level\":\"debug\"",
				"\"key1\":\"value1\"",
				"\"key2\":42",
			},
		},
		{
			name:    "info level",
			logFunc: (*Logger).Infow,
			level:   "info",
			message: "info message",
			keyVals: []interface{}{"key1", "value1"},
			expected: []string{
				"info message",
				"\"level\":\"info\"",
				"\"key1\":\"value1\"",
			},
		},
		{
			name:    "warn level",
			logFunc: (*Logger).Warnw,
			level:   "warn",
			message: "warn message",
			keyVals: []interface{}{"error", "test error"},
			expected: []string{
				"warn message",
				"\"level\":\"warn\"",
				"\"error\":\"test error\"",
			},
		},
		{
			name:    "error level",
			logFunc: (*Logger).Errorw,
			level:   "error",
			message: "error message",
			keyVals: []interface{}{"code", 500},
			expected: []string{
				"error message",
				"\"level\":\"error\"",
				"\"code\":500",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, buf := newTestLogger()
			tt.logFunc(logger, tt.message, tt.keyVals...)

			output := buf.String()
			for _, expected := range tt.expected {
				assert.Contains(t, output, expected)
			}
		})
	}
}

func TestLogger_Aggregation(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	logger.cfg.Aggregate = true
	logger.logCount = newLogCounter()

	// Log the same message multiple times
	for i := 0; i < 5; i++ {
		logger.Debugw("repeated message", "key", "value")
	}

	// Force flush
	for _, count := range logger.logCount.Flush() {
		Log(count.Level, false, count.Msg, "count", 5)
	}

	output := buf.String()
	assert.Contains(t, output, "repeated message")
	assert.Contains(t, output, "\"count\":5")
}

func TestLogger_SetLevel(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()

	// Set level to INFO
	logger.cfg.SetLevel(InfoLevel)

	// Debug messages should not appear
	logger.Debugw("debug message")
	assert.Empty(t, buf.String())

	// Info messages should appear
	logger.Infow("info message")
	assert.Contains(t, buf.String(), "info message")
}

func TestLogger_Init(t *testing.T) {
	t.Parallel()

	buf := &testBuffer{}
	cfg := LoggingConfig{
		Logger:        zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), buf, zap.InfoLevel)).Sugar(),
		Level:         InfoLevel,
		Aggregate:     true,
		FlushInterval: time.Second,
	}

	Init(cfg)
	defer func() {
		Init(NewDefaultLoggingConfig()) // Reset to default config
	}()

	// Test package-level logging functions
	Debugw("debug message") // Should not appear due to INFO level
	Infow("info message", "key", "value")

	output := buf.String()
	assert.NotContains(t, output, "debug message")
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "\"key\":\"value\"")
}

func TestLogger_Sync(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	err := logger.Sync()
	require.NoError(t, err)
}

func TestLogger_InvalidInit(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		Init(LoggingConfig{Logger: nil})
	})
}
