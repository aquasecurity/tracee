package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	l       *zap.Logger
	pkgs    map[string]bool
	metrics bool

	LogCount *LogCounter
}

type LogOrigin struct {
	File string
	Line int
}

type LogCounter struct {
	rwMutex sync.RWMutex
	data    map[LogOrigin]uint32
}

func (lc *LogCounter) update(lo LogOrigin) {
	lc.rwMutex.Lock()
	lc.data[lo]++
	lc.rwMutex.Unlock()
}

func (lc *LogCounter) Lookup(key LogOrigin) (uint32, error) {
	lc.rwMutex.RLock()
	count, found := lc.data[key]
	lc.rwMutex.RUnlock()

	if !found {
		return 0, fmt.Errorf("LogCount key not found: %v", key)
	}

	return count, nil
}

func (lc *LogCounter) Dump() map[LogOrigin]uint32 {
	lc.rwMutex.RLock()
	dump := make(map[LogOrigin]uint32, len(lc.data))
	for k, v := range lc.data {
		dump[k] = v
	}
	lc.rwMutex.RUnlock()

	return dump
}

func newLogCounter() *LogCounter {
	return &LogCounter{
		rwMutex: sync.RWMutex{},
		data:    map[LogOrigin]uint32{},
	}
}

type Field = zap.Field
type Level = zapcore.Level

const (
	DebugLevel  Level = zap.DebugLevel
	InfoLevel   Level = zap.InfoLevel
	WarnLevel   Level = zap.WarnLevel
	ErrorLevel  Level = zap.ErrorLevel
	DPanicLevel Level = zap.DPanicLevel
	PanicLevel  Level = zap.PanicLevel
	FatalLevel  Level = zap.FatalLevel
)

var (
	// TODO: envelope and rename all zap fields
	Any        = zap.Any
	Skip       = zap.Skip
	Binary     = zap.Binary
	Bool       = zap.Bool
	Boolp      = zap.Boolp
	ByteString = zap.ByteString

	Uint32  = zap.Uint32
	Uint32p = zap.Uint32p
	Uint32s = zap.Uint32s

	Float64    = zap.Float64
	Float64p   = zap.Float64p
	Float32    = zap.Float32
	Float32p   = zap.Float32p
	ErrorField = zap.Error

	Durationp = zap.Durationp

	String  = zap.String
	Stringp = zap.Stringp
)

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
	// empty function (from a receiver)
	if possibleLastDot := strings.LastIndexByte(pkg, '.'); possibleLastDot != -1 {
		pkg = pkg[0:possibleLastDot]
	}

	return pkg, file, line
}

func (l *Logger) updateMetrics(file string, line int) {
	lo := LogOrigin{
		File: file,
		Line: line,
	}
	l.LogCount.update(lo)
}

// checkEnabledAndUpdateMetrics returns if package is enabled
// Updates metrics when it is
func (l *Logger) checkEnabledAndUpdateMetrics(skip int) bool {
	pkg, file, line := getCallerInfo(skip + 1)

	// filter out not enabled packages
	if len(l.pkgs) > 0 {
		if _, enabled := l.pkgs[pkg]; !enabled {
			return false
		}
	}

	if l.metrics {
		l.updateMetrics(file, line)
	}

	return true
}

// Log functions

// Debug
func debug(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Debug(msg, fields...)
}

func Debug(msg string, fields ...Field) {
	debug(1, defaultLogger, msg, fields...)
}

func (l *Logger) Debug(msg string, fields ...Field) {
	debug(1, l, msg, fields...)
}

// Info
func info(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Info(msg, fields...)
}

func Info(msg string, fields ...Field) {
	info(1, defaultLogger, msg, fields...)
}

func (l *Logger) Info(msg string, fields ...Field) {
	info(1, l, msg, fields...)
}

// Warn
func warn(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Warn(msg, fields...)
}

func Warn(msg string, fields ...Field) {
	warn(1, defaultLogger, msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...Field) {
	warn(1, l, msg, fields...)
}

// Error
func err(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Error(msg, fields...)
}

func Error(msg string, fields ...Field) {
	err(1, defaultLogger, msg, fields...)
}

func (l *Logger) Error(msg string, fields ...Field) {
	err(1, l, msg, fields...)
}

// DPanic
func dPanic(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.DPanic(msg, fields...)
}

func DPanic(msg string, fields ...Field) {
	dPanic(1, defaultLogger, msg, fields...)
}

func (l *Logger) DPanic(msg string, fields ...Field) {
	dPanic(1, l, msg, fields...)
}

// Panic
func panicLogger(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Panic(msg, fields...)
}

func Panic(msg string, fields ...Field) {
	panicLogger(1, defaultLogger, msg, fields...)
}

func (l *Logger) Panic(msg string, fields ...Field) {
	panicLogger(1, l, msg, fields...)
}

// Fatal
func fatal(skip int, l *Logger, msg string, fields ...Field) {
	if !l.checkEnabledAndUpdateMetrics(skip + 1) {
		return
	}

	l.l.Fatal(msg, fields...)
}

func Fatal(msg string, fields ...Field) {
	fatal(1, defaultLogger, msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...Field) {
	fatal(1, l, msg, fields...)
}

// Sync
func (l *Logger) Sync() error {
	return l.l.Sync()
}

// Default returns default logger
func Default() *Logger {
	return defaultLogger
}

// package level Logger
var defaultLogger = New(os.Stdout, InfoLevel)

func New(w io.Writer, lvl Level, packages ...string) *Logger {
	if w == nil {
		panic("logger writer must be set")
	}

	var (
		cfg     zap.Config
		encoder zapcore.Encoder
		metrics bool
	)

	if lvl == DebugLevel {
		cfg = zap.NewDevelopmentConfig()
		encoder = zapcore.NewConsoleEncoder(cfg.EncoderConfig)
		metrics = true // enabled only for DebugLevel
	} else {
		cfg = zap.NewProductionConfig()
		encoder = zapcore.NewJSONEncoder(cfg.EncoderConfig)
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(w),
		zapcore.Level(lvl),
	)

	pkgs := map[string]bool{}
	for _, pkg := range packages {
		pkgs[pkg] = true
	}

	return &Logger{
		l:        zap.New(core),
		pkgs:     pkgs,
		metrics:  metrics,
		LogCount: newLogCounter(),
	}
}
