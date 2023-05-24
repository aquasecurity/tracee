package logger

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

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

type LoggerInterface interface {
	Debugw(msg string, keyAndValues ...interface{})
	Infow(msg string, keyAndValues ...interface{})
	Warnw(msg string, keyAndValues ...interface{})
	Errorw(msg string, keyAndValues ...interface{})
	Fatalw(msg string, keyAndValues ...interface{})
	Sync() error
}

// Logger struct
type Logger struct {
	l   LoggerInterface
	cfg LoggingConfig

	logCount *logCounter // updated only on debug level and cfg.Aggregate == true
}

// NewLogger function
func NewLogger(cfg LoggerConfig) LoggerInterface {
	return zap.New(zapcore.NewCore(
		cfg.Encoder,
		zapcore.AddSync(cfg.Writer),
		zapcore.Level(cfg.Level),
	)).Sugar()
}

const (
	DefaultLevel         = InfoLevel
	DefaultFlushInterval = time.Duration(3) * time.Second
)

// LoggingConfig defines the configuration of the package level logging.
//
// Users importing tracee as a library may choose to construct a tracee flavored logger with
// NewLogger() or supply their own interface.
//
// Tracee offers aggregation and filtering support on top of any logger implementation complying to it's interface.
type LoggingConfig struct {
	Logger        LoggerInterface
	Filter        LoggerFilter
	Aggregate     bool
	FlushInterval time.Duration
}

// LoggerConfig defines the configuration parameters for constructing tracee's logger implementation.
type LoggerConfig struct {
	Writer  io.Writer
	Level   Level
	Encoder Encoder
}

func defaultEncoder() Encoder {
	return NewJSONEncoder(NewProductionEncoderConfig())
}

func NewDefaultLoggerConfig() LoggerConfig {
	return LoggerConfig{
		Writer:  os.Stderr,
		Level:   DefaultLevel,
		Encoder: defaultEncoder(),
	}
}

func NewDefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Logger:        NewLogger(NewDefaultLoggerConfig()),
		Filter:        NewLoggerFilter(),
		Aggregate:     false,
		FlushInterval: DefaultFlushInterval,
	}
}

func (l *Logger) updateCounter(file string, line int, lvl Level, msg string) {
	l.logCount.update(logOrigin{
		File:  file,
		Line:  line,
		Level: lvl,
		Msg:   msg,
	})
}

// aggregateLog will update the log counter if aggregation is enabled.
// It returns true if the aggregation was done.
func aggregateLog(skip int, l *Logger, lvl Level, msg string) bool {
	if l.cfg.Aggregate {
		callerInfo := getCallerInfo(skip + 1)
		l.updateCounter(callerInfo.file, callerInfo.line, lvl, msg)

		return true
	}

	return false
}

// Log functions

// Log is a generic helper that allows logging by choosing the desired level and if the aggregation should be done.
// It does NOT override those options.
// For the case where innerAggregation is set to true, it will only aggregate if pkg logger's aggregation config is also set to true.
func Log(lvl Level, innerAggregation bool, msg string, keysAndValues ...interface{}) {
	if innerAggregation {
		switch lvl {
		case DebugLevel:
			debugw(1, pkgLogger, msg, keysAndValues...)
		case InfoLevel:
			infow(1, pkgLogger, msg, keysAndValues...)
		case WarnLevel:
			warnw(1, pkgLogger, msg, keysAndValues...)
		case ErrorLevel:
			errorw(1, pkgLogger, msg, keysAndValues...)
		default:
			infoKVs := append(make([]interface{}, 0), "level", int(lvl), "msg", msg)
			keysAndValues = append(infoKVs, keysAndValues...)
			errorw(1, pkgLogger, "unspecified log level", keysAndValues...)
		}
	} else {
		// skip pkg aggregation logic calling inner logger directly
		switch lvl {
		case DebugLevel:
			pkgLogger.l.Debugw(msg, keysAndValues...)
		case InfoLevel:
			pkgLogger.l.Infow(msg, keysAndValues...)
		case WarnLevel:
			pkgLogger.l.Warnw(msg, keysAndValues...)
		case ErrorLevel:
			pkgLogger.l.Errorw(msg, keysAndValues...)
		default:
			infoKVs := append(make([]interface{}, 0), "level", int(lvl), "msg", msg)
			keysAndValues = append(infoKVs, keysAndValues...)
			pkgLogger.l.Errorw("unspecified log level", keysAndValues...)
		}
	}
}

func formatCallFlow(funcNames []string) string {
	fns := make([]string, len(funcNames))
	for i, fName := range funcNames {
		fns[i] = fName + "()"
	}

	return strings.Join(fns, " < ")
}

// Debug
func debugw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, DebugLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	if !shouldOutput(msg, DebugLevel, callerInfo) {
		return
	}

	origin := strings.Join([]string{callerInfo.pkg, callerInfo.file, strconv.Itoa(callerInfo.line)}, ":")
	calls := formatCallFlow(callerInfo.functions)
	keysAndValues = append(keysAndValues, "origin", origin, "calls", calls)

	l.l.Debugw(msg, keysAndValues...)
}

func Debugw(msg string, keysAndValues ...interface{}) {
	debugw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	debugw(1, l, msg, keysAndValues...)
}

// Info
func infow(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, InfoLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	if !shouldOutput(msg, InfoLevel, callerInfo) {
		return
	}

	l.l.Infow(msg, keysAndValues...)
}

func Infow(msg string, keysAndValues ...interface{}) {
	infow(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
	infow(1, l, msg, keysAndValues...)
}

// Warn
func warnw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, WarnLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	if !shouldOutput(msg, WarnLevel, callerInfo) {
		return
	}

	l.l.Warnw(msg, keysAndValues...)
}

func Warnw(msg string, keysAndValues ...interface{}) {
	warnw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Warnw(msg string, keysAndValues ...interface{}) {
	warnw(1, l, msg, keysAndValues...)
}

// Error
func errorw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, ErrorLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	if !shouldOutput(msg, ErrorLevel, callerInfo) {
		return
	}

	l.l.Errorw(msg, keysAndValues...)
}

func Errorw(msg string, keysAndValues ...interface{}) {
	errorw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Errorw(msg string, keysAndValues ...interface{}) {
	errorw(1, l, msg, keysAndValues...)
}

// Fatal
func fatalw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, FatalLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	if !shouldOutput(msg, FatalLevel, callerInfo) {
		return
	}

	l.l.Fatalw(msg, keysAndValues...)
}

func Fatalw(msg string, keysAndValues ...interface{}) {
	fatalw(1, pkgLogger, msg, keysAndValues...)
}

func (l *Logger) Fatalw(msg string, keysAndValues ...interface{}) {
	fatalw(1, l, msg, keysAndValues...)
}

// Sync
func (l *Logger) Sync() error {
	return l.l.Sync()
}

var (
	// Package-level Logger
	pkgLogger = &Logger{}
)

// Current returns the package-level base logger
func Current() *Logger {
	return pkgLogger
}

// SetLogger sets package-level base logger
// It's not thread safe so if required use it always at the beginning
func SetLogger(l LoggerInterface) {
	if l == nil {
		panic("Logger cannot be nil")
	}

	pkgLogger.l = l
}

// Init sets the package-level base logger using given config
// It's not thread safe so if required use it always at the beginning
func Init(cfg LoggingConfig) {
	// set the config
	pkgLogger.cfg = cfg

	if cfg.Logger == nil {
		panic("can't initialize a nil Logger")
	}

	pkgLogger.l = cfg.Logger
	pkgLogger.logCount = newLogCounter()

	// Flush aggregated logs every interval
	if pkgLogger.cfg.Aggregate {
		go func() {
			for range time.Tick(pkgLogger.cfg.FlushInterval) {
				for lo, count := range pkgLogger.logCount.Flush() {
					Log(lo.Level, false, lo.Msg,
						"origin", fmt.Sprintf("%s:%d", lo.File, lo.Line),
						"count", count,
					)
				}
			}
		}()
	}
}

// Make sure tests don't crash when logging
func init() {
	Init(NewDefaultLoggingConfig())
}
