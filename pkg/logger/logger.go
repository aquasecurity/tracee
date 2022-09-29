package logger

import (
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	Level = zapcore.Level
)

const (
	DebugLevel  Level = zap.DebugLevel
	InfoLevel   Level = zap.InfoLevel
	WarnLevel   Level = zap.WarnLevel
	ErrorLevel  Level = zap.ErrorLevel
	DPanicLevel Level = zap.DPanicLevel
	PanicLevel  Level = zap.PanicLevel
	FatalLevel  Level = zap.FatalLevel
)

type Config = zap.Config

var (
	NewDevelopmentConfig = zap.NewDevelopmentConfig
	NewProductionConfig  = zap.NewProductionConfig
)

type Encoder = zapcore.Encoder

var (
	NewConsoleEncoder = zapcore.NewConsoleEncoder
	NewJSONEncoder    = zapcore.NewJSONEncoder
)

type EncoderConfig = zapcore.EncoderConfig

var (
	NewDevelopmentEncoderConfig = zap.NewDevelopmentEncoderConfig
	NewProductionEncoderConfig  = zap.NewProductionEncoderConfig
)

// Logger struct
type Logger struct {
	l   *zap.SugaredLogger
	cfg *LoggerConfig

	LogCount *LogCounter // updated only on debug level and cfg.Aggregate == true
}

// NewLogger function
func NewLogger(cfg *LoggerConfig) *Logger {
	if cfg == nil {
		panic("LoggerConfig cannot be nil")
	}

	core := zapcore.NewCore(
		cfg.Encoder,
		zapcore.AddSync(cfg.Writer),
		zapcore.Level(cfg.Level),
	)

	return &Logger{
		l:        zap.New(core).Sugar(),
		cfg:      cfg,
		LogCount: newLogCounter(),
	}
}

type LoggerConfig struct {
	Writer    io.Writer
	Level     Level
	Encoder   Encoder
	Aggregate bool
}

func defaultEncoder() Encoder {
	return NewJSONEncoder(NewProductionEncoderConfig())
}

func NewDefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Writer:    os.Stderr,
		Level:     InfoLevel,
		Encoder:   defaultEncoder(),
		Aggregate: false,
	}
}

type LogOrigin struct {
	File string
	Line int
}

type LogCounter struct {
	rwMutex sync.RWMutex
	data    map[LogOrigin]uint32
}

func (lc *LogCounter) update(lo LogOrigin) (new bool) {
	lc.rwMutex.Lock()
	defer lc.rwMutex.Unlock()
	_, found := lc.data[lo]
	lc.data[lo]++

	return !found
}

func (lc *LogCounter) Lookup(key LogOrigin) (count uint32, found bool) {
	lc.rwMutex.RLock()
	defer lc.rwMutex.RUnlock()
	count, found = lc.data[key]

	return
}

func (lc *LogCounter) Dump() map[LogOrigin]uint32 {
	lc.rwMutex.RLock()
	defer lc.rwMutex.RUnlock()
	dump := make(map[LogOrigin]uint32, len(lc.data))
	for k, v := range lc.data {
		dump[k] = v
	}

	return dump
}

func newLogCounter() *LogCounter {
	return &LogCounter{
		rwMutex: sync.RWMutex{},
		data:    map[LogOrigin]uint32{},
	}
}

// getCallerInfo retuns package, file and line from a function
// based on the given number of skips (stack frames).
func getCallerInfo(skip int) (pkg, file string, line int) {
	pc, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		panic("could not get runtime caller information")
	}

	funcName := runtime.FuncForPC(pc).Name()
	lastSlash := strings.LastIndexByte(funcName, '/')
	if lastSlash < 0 {
		lastSlash = 0
	} else {
		lastSlash++
	}
	lastDot := strings.LastIndexByte(funcName, '.')
	pkg = funcName[lastSlash:lastDot]
	// check if it's from a receiver
	if possibleLastDot := strings.LastIndexByte(pkg, '.'); possibleLastDot != -1 {
		pkg = pkg[0:possibleLastDot]
	}

	return pkg, file, line
}

func (l *Logger) updateCounter(file string, line int) (new bool) {
	return l.LogCount.update(LogOrigin{
		File: file,
		Line: line,
	})
}

// isAggregateSetAndIsLogNotNew checks
// - if logs aggregation is set, so:
//   - updates log count;
//   - returns true if the log is not new, (avoiding writing).
func isAggregateSetAndIsLogNotNew(skip int, l *Logger) bool {
	if l.cfg.Aggregate {
		_, file, line := getCallerInfo(skip + 1)
		new := l.updateCounter(file, line)

		return !new
	}

	return false
}

// Log functions

// Debug
func debugw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if l.cfg.Level > DebugLevel {
		return
	}

	if isAggregateSetAndIsLogNotNew(skip+1, l) {
		return
	}

	l.l.Debugw(msg, keysAndValues...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	debugw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	debugw(1, l, msg, keysAndValues...)
}

// Info
func infow(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if isAggregateSetAndIsLogNotNew(skip+1, l) {
		return
	}

	l.l.Infow(msg, keysAndValues...)
}

func Info(msg string, keysAndValues ...interface{}) {
	infow(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	infow(1, l, msg, keysAndValues...)
}

// Warn
func warnw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if l.cfg.Aggregate {
		_, file, line := getCallerInfo(skip + 1)
		if new := l.updateCounter(file, line); !new {
			return
		}
	}

	l.l.Warnw(msg, keysAndValues...)
}

func Warn(msg string, keysAndValues ...interface{}) {
	warnw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	warnw(1, l, msg, keysAndValues...)
}

// Error
func errorw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if isAggregateSetAndIsLogNotNew(skip+1, l) {
		return
	}

	l.l.Errorw(msg, keysAndValues...)
}

func Error(msg string, keysAndValues ...interface{}) {
	errorw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	errorw(1, l, msg, keysAndValues...)
}

// Fatal
func fatalw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if isAggregateSetAndIsLogNotNew(skip+1, l) {
		return
	}

	l.l.Fatalw(msg, keysAndValues...)
}

func Fatal(msg string, keysAndValues ...interface{}) {
	fatalw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	fatalw(1, l, msg, keysAndValues...)
}

// Sync
func (l *Logger) Sync() error {
	return l.l.Sync()
}

const (
	TRACEE_LOGGER_LVL       = "TRACEE_LOGGER_LVL"
	TRACEE_LOGGER_ENCODER   = "TRACEE_LOGGER_ENCODER"
	TRACEE_LOGGER_AGGREGATE = "TRACEE_LOGGER_AGGREGATE"
)

// getLoggerLevelFromEnv returns logger level set through TRACEE_LOGGER_LVL
// environment variable, updating the flag setFromEnv.
// If the given level is not correct, this returns the default level.
func getLoggerLevelFromEnv() (lvl Level) {
	lvlEnv := os.Getenv(TRACEE_LOGGER_LVL)
	fromEnv := true

	switch lvlEnv {
	case "debug":
		lvl = DebugLevel
	case "info":
		lvl = InfoLevel
	case "warn":
		lvl = WarnLevel
	case "error":
		lvl = ErrorLevel
	case "dpanic":
		lvl = DPanicLevel
	case "panic":
		lvl = PanicLevel
	case "fatal":
		lvl = FatalLevel
	default:
		fromEnv = false
		lvl = InfoLevel
	}

	if !setFromEnv {
		setFromEnv = fromEnv
	}
	return
}

// getLoggerEncoderFromEnv returns logger encoder set through TRACEE_LOGGER_ENCODER
// environment variable, updating the flag setFromEnv.
// If the given encoder is not correct, this returns the default encoder.
func getLoggerEncoderFromEnv(lvl Level) (enc Encoder) {
	encEnv := os.Getenv(TRACEE_LOGGER_ENCODER)
	fromEnv := true
	devEncoderConfig := NewDevelopmentEncoderConfig()
	prodEncoderConfig := NewProductionEncoderConfig()

	switch encEnv {
	case "json":
		if lvl == DebugLevel {
			enc = NewJSONEncoder(devEncoderConfig)
		} else {
			enc = NewJSONEncoder(prodEncoderConfig)
		}
	case "console":
		if lvl == DebugLevel {
			enc = NewConsoleEncoder(devEncoderConfig)
		} else {
			enc = NewConsoleEncoder(prodEncoderConfig)
		}
	default:
		fromEnv = false
		enc = defaultEncoder()
	}

	if !setFromEnv {
		setFromEnv = fromEnv
	}
	return
}

// getLoggerAggregateFromEnv returns logger Aggregate boolean set through TRACEE_LOGGER_AGGREGATE
// environment variable, updating the flag setFromEnv.
// If the given value is not correct, this returns false.
func getLoggerAggregateFromEnv() (aggregate bool) {
	aggEnv := os.Getenv(TRACEE_LOGGER_AGGREGATE)
	fromEnv := true

	switch aggEnv {
	case "true":
		aggregate = true
	case "false":
		aggregate = false
	default:
		fromEnv = false
		aggregate = false
	}

	if !setFromEnv {
		setFromEnv = fromEnv
	}
	return
}

var (
	// Package-level Logger
	pkgLogger *Logger

	setFromEnv bool
)

func IsSetFromEnv() bool {
	return setFromEnv
}

func init() {
	lvl := getLoggerLevelFromEnv()
	enc := getLoggerEncoderFromEnv(lvl)
	agg := getLoggerAggregateFromEnv()

	pkgLogger = NewLogger(
		&LoggerConfig{
			Writer:    os.Stderr,
			Level:     lvl,
			Encoder:   enc,
			Aggregate: agg,
		},
	)
}

// Base returns the package-level base logger
func Base() *Logger {
	return pkgLogger
}

// SetBase sets package-level base logger
// It's not thread safe so if required use it always at the beggining
func SetBase(l *Logger) {
	if l == nil {
		panic("Logger cannot be nil")
	}

	pkgLogger = l
}

// Init sets the package-level base logger using given config
// It's not thread safe so if required use it always at the beggining
func Init(cfg *LoggerConfig) {
	if cfg == nil {
		panic("LoggerConfig cannot be nil")
	}

	SetBase(NewLogger(cfg))
}
