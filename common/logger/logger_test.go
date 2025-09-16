package logger

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Mock logger for testing
type mockLogger struct {
	debugCalls []logCall
	infoCalls  []logCall
	warnCalls  []logCall
	errorCalls []logCall
	fatalCalls []logCall
	syncCalled bool
	mu         sync.Mutex
}

type logCall struct {
	msg           string
	keysAndValues []interface{}
}

func newMockLogger() *mockLogger {
	return &mockLogger{}
}

func (m *mockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugCalls = append(m.debugCalls, logCall{msg, keysAndValues})
}

func (m *mockLogger) Infow(msg string, keysAndValues ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoCalls = append(m.infoCalls, logCall{msg, keysAndValues})
}

func (m *mockLogger) Warnw(msg string, keysAndValues ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnCalls = append(m.warnCalls, logCall{msg, keysAndValues})
}

func (m *mockLogger) Errorw(msg string, keysAndValues ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorCalls = append(m.errorCalls, logCall{msg, keysAndValues})
}

func (m *mockLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fatalCalls = append(m.fatalCalls, logCall{msg, keysAndValues})
}

func (m *mockLogger) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalled = true
	return nil
}

func (m *mockLogger) getCalls(level Level) []logCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch level {
	case DebugLevel:
		return append([]logCall(nil), m.debugCalls...)
	case InfoLevel:
		return append([]logCall(nil), m.infoCalls...)
	case WarnLevel:
		return append([]logCall(nil), m.warnCalls...)
	case ErrorLevel:
		return append([]logCall(nil), m.errorCalls...)
	case FatalLevel:
		return append([]logCall(nil), m.fatalCalls...)
	default:
		return nil
	}
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		expected zapcore.Level
	}{
		{"debug level", DebugLevel, zap.DebugLevel},
		{"info level", InfoLevel, zap.InfoLevel},
		{"warn level", WarnLevel, zap.WarnLevel},
		{"error level", ErrorLevel, zap.ErrorLevel},
		{"dpanic level", DPanicLevel, zap.DPanicLevel},
		{"panic level", PanicLevel, zap.PanicLevel},
		{"fatal level", FatalLevel, zap.FatalLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level)
		})
	}

	// Test default values
	assert.Equal(t, InfoLevel, DefaultLevel)
	assert.Equal(t, time.Duration(3)*time.Second, DefaultFlushInterval)
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	cfg := LoggerConfig{
		Writer:  &buf,
		Level:   NewAtomicLevelAt(InfoLevel),
		Encoder: NewJSONEncoder(NewProductionEncoderConfig()),
	}

	logger := NewLogger(cfg)
	require.NotNil(t, logger)

	// Test that it logs at the correct level
	logger.Infow("test message", "key", "value")
	logger.Debugw("debug message") // Should not appear due to level

	assert.Contains(t, buf.String(), "test message")
	assert.NotContains(t, buf.String(), "debug message")
}

func TestDefaultEncoder(t *testing.T) {
	encoder := defaultEncoder()
	assert.NotNil(t, encoder)
}

func TestNewDefaultLoggerConfig(t *testing.T) {
	cfg := NewDefaultLoggerConfig()

	assert.NotNil(t, cfg.Writer)
	assert.NotNil(t, cfg.Level)
	assert.NotNil(t, cfg.Encoder)
	assert.Equal(t, DefaultLevel, cfg.Level.Level())
}

func TestNewDefaultLoggingConfig(t *testing.T) {
	cfg := NewDefaultLoggingConfig()

	assert.NotNil(t, cfg.Logger)
	assert.NotNil(t, cfg.LoggerConfig.Writer)
	assert.NotNil(t, cfg.LoggerConfig.Level)
	assert.NotNil(t, cfg.LoggerConfig.Encoder)
	assert.False(t, cfg.Aggregate)
	assert.Equal(t, DefaultFlushInterval, cfg.FlushInterval)
}

func TestLoggingConfig_SetLevel(t *testing.T) {
	cfg := NewDefaultLoggingConfig()

	// Test setting different levels
	cfg.SetLevel(ErrorLevel)
	assert.Equal(t, ErrorLevel, cfg.LoggerConfig.Level.Level())

	cfg.SetLevel(DebugLevel)
	assert.Equal(t, DebugLevel, cfg.LoggerConfig.Level.Level())
}

func TestFormatCallFlow(t *testing.T) {
	tests := []struct {
		name      string
		funcNames []string
		expected  string
	}{
		{
			name:      "single function",
			funcNames: []string{"main"},
			expected:  "main()",
		},
		{
			name:      "multiple functions",
			funcNames: []string{"main", "foo", "bar"},
			expected:  "main() < foo() < bar()",
		},
		{
			name:      "empty slice",
			funcNames: []string{},
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatCallFlow(tt.funcNames)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	// Save original logger
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	mock := newMockLogger()

	// Test SetLogger with nil should panic
	assert.Panics(t, func() {
		SetLogger(nil)
	})

	// Test SetLogger with valid logger
	SetLogger(mock)
	retrieved := GetLogger()
	assert.Equal(t, mock, retrieved)

	// Test Current
	current := Current()
	assert.NotNil(t, current)
	assert.Equal(t, mock, current.l)
}

func TestInit(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	originalLogCount := pkgLogger.logCount
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
		pkgLogger.logCount = originalLogCount
	}()

	mock := newMockLogger()
	cfg := LoggingConfig{
		Logger:        mock,
		LoggerConfig:  NewDefaultLoggerConfig(),
		Filter:        NewLoggerFilter(),
		Aggregate:     false,
		FlushInterval: time.Millisecond * 10,
	}

	// Test Init with nil logger should panic
	invalidCfg := cfg
	invalidCfg.Logger = nil
	assert.Panics(t, func() {
		Init(invalidCfg)
	})

	// Test Init with valid config
	Init(cfg)
	assert.Equal(t, mock, pkgLogger.l)
	assert.Equal(t, cfg, pkgLogger.cfg)
	assert.NotNil(t, pkgLogger.logCount)
}

func TestLoggerMethods(t *testing.T) {
	mock := newMockLogger()
	logger := &Logger{
		l:   mock,
		cfg: NewDefaultLoggingConfig(),
	}

	tests := []struct {
		name     string
		logFunc  func()
		level    Level
		expected string
	}{
		{
			name: "debug",
			logFunc: func() {
				logger.Debugw("debug message", "key", "value")
			},
			level:    DebugLevel,
			expected: "debug message",
		},
		{
			name: "info",
			logFunc: func() {
				logger.Infow("info message", "key", "value")
			},
			level:    InfoLevel,
			expected: "info message",
		},
		{
			name: "warn",
			logFunc: func() {
				logger.Warnw("warn message", "key", "value")
			},
			level:    WarnLevel,
			expected: "warn message",
		},
		{
			name: "error",
			logFunc: func() {
				logger.Errorw("error message", "key", "value")
			},
			level:    ErrorLevel,
			expected: "error message",
		},
		{
			name: "fatal",
			logFunc: func() {
				logger.Fatalw("fatal message", "key", "value")
			},
			level:    FatalLevel,
			expected: "fatal message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.logFunc()
			calls := mock.getCalls(tt.level)
			require.Len(t, calls, 1)
			assert.Equal(t, tt.expected, calls[0].msg)

			// Debug logs include additional origin and calls information
			if tt.level == DebugLevel {
				assert.Contains(t, calls[0].keysAndValues, "key")
				assert.Contains(t, calls[0].keysAndValues, "value")
				assert.Contains(t, calls[0].keysAndValues, "origin")
				assert.Contains(t, calls[0].keysAndValues, "calls")
			} else {
				assert.Equal(t, []interface{}{"key", "value"}, calls[0].keysAndValues)
			}
		})
	}
}

func TestLoggerSync(t *testing.T) {
	mock := newMockLogger()
	logger := &Logger{l: mock}

	err := logger.Sync()
	assert.NoError(t, err)
	assert.True(t, mock.syncCalled)
}

func TestLogWithDifferentLevels(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	mock := newMockLogger()
	cfg := NewDefaultLoggingConfig()
	cfg.Logger = mock
	Init(cfg)

	tests := []struct {
		name             string
		level            Level
		innerAggregation bool
		expectedLevel    Level
		expectedMsg      string
	}{
		{"debug with aggregation", DebugLevel, true, DebugLevel, "debug message"},
		{"info with aggregation", InfoLevel, true, InfoLevel, "info message"},
		{"warn with aggregation", WarnLevel, true, WarnLevel, "warn message"},
		{"error with aggregation", ErrorLevel, true, ErrorLevel, "error message"},
		{"debug without aggregation", DebugLevel, false, DebugLevel, "debug message"},
		{"info without aggregation", InfoLevel, false, InfoLevel, "info message"},
		{"warn without aggregation", WarnLevel, false, WarnLevel, "warn message"},
		{"error without aggregation", ErrorLevel, false, ErrorLevel, "error message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear previous calls
			mock.debugCalls = nil
			mock.infoCalls = nil
			mock.warnCalls = nil
			mock.errorCalls = nil

			Log(tt.level, tt.innerAggregation, tt.expectedMsg, "key", "value")
			calls := mock.getCalls(tt.expectedLevel)
			require.Len(t, calls, 1)
			assert.Equal(t, tt.expectedMsg, calls[0].msg)
		})
	}
}

func TestLogWithInvalidLevel(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	mock := newMockLogger()
	cfg := NewDefaultLoggingConfig()
	cfg.Logger = mock
	Init(cfg)

	// Test with invalid level (aggregation enabled)
	Log(Level(99), true, "test message", "key", "value")
	calls := mock.getCalls(ErrorLevel)
	require.Len(t, calls, 1)
	assert.Equal(t, "unspecified log level", calls[0].msg)
	assert.Contains(t, calls[0].keysAndValues, "level")
	assert.Contains(t, calls[0].keysAndValues, 99)

	// Test with invalid level (aggregation disabled)
	mock.errorCalls = nil // Clear previous calls
	Log(Level(99), false, "test message", "key", "value")
	calls = mock.getCalls(ErrorLevel)
	require.Len(t, calls, 1)
	assert.Equal(t, "unspecified log level", calls[0].msg)
}

func TestPackageLevelSetLevel(t *testing.T) {
	// Save original state
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.cfg = originalCfg
	}()

	// Initialize with a proper config
	cfg := NewDefaultLoggingConfig()
	pkgLogger.cfg = cfg

	SetLevel(ErrorLevel)
	assert.Equal(t, ErrorLevel, pkgLogger.cfg.LoggerConfig.Level.Level())
}

func TestPackageLevelLoggingFunctions(t *testing.T) {
	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	mock := newMockLogger()
	cfg := NewDefaultLoggingConfig()
	cfg.Logger = mock
	Init(cfg)

	// Test package-level logging functions
	Debugw("debug message", "key", "value")
	Infow("info message", "key", "value")
	Warnw("warn message", "key", "value")
	Errorw("error message", "key", "value")

	// Verify calls were made
	assert.Len(t, mock.getCalls(DebugLevel), 1)
	assert.Len(t, mock.getCalls(InfoLevel), 1)
	assert.Len(t, mock.getCalls(WarnLevel), 1)
	assert.Len(t, mock.getCalls(ErrorLevel), 1)
}

func TestLogCounterFunctionality(t *testing.T) {
	lc := newLogCounter()
	assert.NotNil(t, lc)
	assert.NotNil(t, lc.data)

	// Test update
	origin := logOrigin{
		File:  "test.go",
		Line:  10,
		Level: InfoLevel,
		Msg:   "test message",
	}

	lc.update(origin)
	lc.update(origin) // Update again to test increment

	// Test Lookup
	count, found := lc.Lookup(origin)
	assert.True(t, found)
	assert.Equal(t, uint32(2), count)

	// Test Lookup with non-existing key
	nonExistentOrigin := logOrigin{
		File:  "other.go",
		Line:  20,
		Level: ErrorLevel,
		Msg:   "other message",
	}
	count, found = lc.Lookup(nonExistentOrigin)
	assert.False(t, found)
	assert.Equal(t, uint32(0), count)

	// Test Dump (non-flushing)
	dump := lc.Dump()
	assert.Len(t, dump, 1)
	assert.Equal(t, uint32(2), dump[origin])

	// Verify data is still there after dump
	count, found = lc.Lookup(origin)
	assert.True(t, found)
	assert.Equal(t, uint32(2), count)

	// Test Flush (clears data)
	flushed := lc.Flush()
	assert.Len(t, flushed, 1)
	assert.Equal(t, uint32(2), flushed[origin])

	// Verify data is cleared after flush
	count, found = lc.Lookup(origin)
	assert.False(t, found)
	assert.Equal(t, uint32(0), count)
}

func TestAggregateLog(t *testing.T) {
	logger := &Logger{
		cfg: LoggingConfig{
			Aggregate: true,
		},
		logCount: newLogCounter(),
	}

	ci := &callerInfo{
		file: "test.go",
		line: 10,
	}

	// Test with aggregation enabled
	result := aggregateLog(logger, InfoLevel, "test message", ci)
	assert.True(t, result)

	// Verify counter was updated
	origin := logOrigin{
		File:  "test.go",
		Line:  10,
		Level: InfoLevel,
		Msg:   "test message",
	}
	count, found := logger.logCount.Lookup(origin)
	assert.True(t, found)
	assert.Equal(t, uint32(1), count)

	// Test with aggregation disabled
	logger.cfg.Aggregate = false
	result = aggregateLog(logger, InfoLevel, "test message", ci)
	assert.False(t, result)
}

// Test real logger integration
func TestRealLoggerIntegration(t *testing.T) {
	// Use zaptest for safe testing of actual logging
	var buf bytes.Buffer
	core := zapcore.NewCore(
		NewJSONEncoder(NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.InfoLevel,
	)
	zapLogger := zap.New(core).Sugar()

	cfg := LoggingConfig{
		Logger:        zapLogger,
		LoggerConfig:  NewDefaultLoggerConfig(),
		Filter:        NewLoggerFilter(),
		Aggregate:     false,
		FlushInterval: time.Millisecond,
	}

	// Save original state
	originalLogger := pkgLogger.l
	originalCfg := pkgLogger.cfg
	defer func() {
		pkgLogger.l = originalLogger
		pkgLogger.cfg = originalCfg
	}()

	Init(cfg)

	// Test actual logging
	Infow("test message", "key", "value")

	// Sync to ensure message is written
	zapLogger.Sync()

	logOutput := buf.String()
	assert.Contains(t, logOutput, "test message")
	assert.Contains(t, logOutput, "key")
	assert.Contains(t, logOutput, "value")
}

func TestUpdateCounter(t *testing.T) {
	logger := &Logger{
		logCount: newLogCounter(),
	}

	logger.updateCounter("test.go", 10, InfoLevel, "test message")

	origin := logOrigin{
		File:  "test.go",
		Line:  10,
		Level: InfoLevel,
		Msg:   "test message",
	}

	count, found := logger.logCount.Lookup(origin)
	assert.True(t, found)
	assert.Equal(t, uint32(1), count)
}
