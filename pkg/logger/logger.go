package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

const (
	DefaultLevel         = InfoLevel
	DefaultFlushInterval = time.Duration(3) * time.Second
)

type LoggerConfig struct {
	Writer        io.Writer
	Level         Level
	Encoder       Encoder
	Aggregate     bool
	FlushInterval time.Duration
}

func defaultEncoder() Encoder {
	return NewJSONEncoder(NewProductionEncoderConfig())
}

func NewDefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Writer:        os.Stderr,
		Level:         DefaultLevel,
		Encoder:       defaultEncoder(),
		Aggregate:     false,
		FlushInterval: DefaultFlushInterval,
	}
}

type LogOrigin struct {
	File  string
	Line  int
	Level Level
	Msg   string
}

type LogCounter struct {
	rwMutex sync.RWMutex
	data    map[LogOrigin]uint32
}

func (lc *LogCounter) update(lo LogOrigin) {
	lc.rwMutex.Lock()
	defer lc.rwMutex.Unlock()
	lc.data[lo]++
}

func (lc *LogCounter) Lookup(key LogOrigin) (count uint32, found bool) {
	lc.rwMutex.RLock()
	defer lc.rwMutex.RUnlock()
	count, found = lc.data[key]

	return
}

func (lc *LogCounter) dump(flush bool) map[LogOrigin]uint32 {
	lc.rwMutex.RLock()
	defer lc.rwMutex.RUnlock()
	dump := make(map[LogOrigin]uint32, len(lc.data))
	for k, v := range lc.data {
		dump[k] = v
		if flush {
			delete(lc.data, k)
		}
	}
	return dump
}

func (lc *LogCounter) Dump() map[LogOrigin]uint32 {
	return lc.dump(false)
}

func (lc *LogCounter) Flush() map[LogOrigin]uint32 {
	return lc.dump(true)
}

func newLogCounter() *LogCounter {
	return &LogCounter{
		rwMutex: sync.RWMutex{},
		data:    map[LogOrigin]uint32{},
	}
}

type callerInfo struct {
	pkg       string
	file      string
	line      int
	functions []string
}

// getCallerInfo retuns package, file and line from a function
// based on the given number of skips (stack frames).
func getCallerInfo(skip int) *callerInfo {
	var (
		pkg       string
		file      string
		line      int
		functions []string
	)

	// maximum depth of 20
	pcs := make([]uintptr, 20)
	n := runtime.Callers(skip+2, pcs)
	pcs = pcs[:n-1]

	frames := runtime.CallersFrames(pcs)
	firstCaller := true
	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		fn := frame.Function
		fnStart := strings.LastIndexByte(fn, '/')
		if fnStart == -1 {
			fnStart = 0
		} else {
			fnStart++
		}

		fn = fn[fnStart:]
		pkgEnd := strings.IndexByte(fn, '.')
		if pkgEnd == -1 {
			fnStart = 0
		} else {
			fnStart = pkgEnd + 1
		}
		functions = append(functions, fn[fnStart:])

		if firstCaller {
			line = frame.Line
			file = frame.File
			// set file as relative path
			pat := "tracee/"
			traceeIndex := strings.Index(file, pat)
			if traceeIndex != -1 {
				file = file[traceeIndex+len(pat):]
			}
			pkg = fn[:pkgEnd]

			firstCaller = false
		}
	}

	return &callerInfo{
		pkg:       pkg,
		file:      file,
		line:      line,
		functions: functions,
	}
}

func (l *Logger) updateCounter(file string, line int, lvl Level, msg string) {
	l.LogCount.update(LogOrigin{
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
	fns := make([]string, 0)
	for _, fName := range funcNames {
		fns = append(fns, fName+"()")
	}

	return strings.Join(fns, " < ")
}

// Debug
func debugw(skip int, l *Logger, msg string, keysAndValues ...interface{}) {
	if aggregateLog(skip+1, l, DebugLevel, msg) {
		return
	}

	callerInfo := getCallerInfo(skip + 1)
	origin := strings.Join([]string{callerInfo.pkg, callerInfo.file, strconv.Itoa(callerInfo.line)}, ":")
	calls := formatCallFlow(callerInfo.functions)
	keysAndValues = append(keysAndValues, "origin", origin, "calls", calls)

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
	if aggregateLog(skip+1, l, InfoLevel, msg) {
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
	if aggregateLog(skip+1, l, WarnLevel, msg) {
		return
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
	if aggregateLog(skip+1, l, ErrorLevel, msg) {
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
	if aggregateLog(skip+1, l, FatalLevel, msg) {
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
		lvl = DefaultLevel
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

// NOTE: init() functions are executed in the lexical order (package names).
func init() {
	// It may have already been initialized from another package
	if pkgLogger != nil {
		return
	}

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

	// Flush aggregated logs every interval
	if pkgLogger.cfg.Aggregate {
		go func() {
			for range time.Tick(pkgLogger.cfg.FlushInterval) {
				for lo, count := range pkgLogger.LogCount.Flush() {
					Log(lo.Level, false, lo.Msg,
						"origin", fmt.Sprintf("%s:%d", lo.File, lo.Line),
						"count", count,
					)
				}
			}
		}()
	}
}

// GetLevel returns the logger level
func GetLevel() Level {
	return pkgLogger.cfg.Level
}

// HasDebugLevel returns true if logger has debug level
func HasDebugLevel() bool {
	return pkgLogger.cfg.Level == DebugLevel
}
