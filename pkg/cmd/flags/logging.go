package flags

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

const (
	LoggingFlagShort    = "l"
	LoggingFlag         = "logging"
	DefaultLogLevelFlag = level + "=" + levelInfo

	level                    = "level"
	levelDebug               = "debug"
	levelInfo                = "info"
	levelWarn                = "warn"
	levelError               = "error"
	levelFatal               = "fatal"
	file                     = "file"
	filterKey                = "filters"
	filterInclude            = "include"
	filterExclude            = "exclude"
	filterLibbpf             = "libbpf"
	aggregation              = "aggregate"
	aggregationFlushInterval = "flush-interval"
)

// LogConfig is the configuration for the logger.
type LogConfig struct {
	Level     string             `mapstructure:"level"`
	File      string             `mapstructure:"file"`
	Aggregate LogAggregateConfig `mapstructure:"aggregate"`
	Filters   LogFilterConfig    `mapstructure:"filters"`

	loggerCfg     logger.LoggerConfig
	filter        logger.LoggerFilter
	aggregate     bool
	flushInterval time.Duration
}

// LogAggregateConfig is the configuration for the log aggregation.
type LogAggregateConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	FlushInterval string `mapstructure:"flush-interval"`
}

// LogFilterConfig is the configuration for the log filters.
type LogFilterConfig struct {
	Include LogFilterAttributes `mapstructure:"include"`
	Exclude LogFilterAttributes `mapstructure:"exclude"`
}

// LogFilterAttributes is the attributes for the log filters.
type LogFilterAttributes struct {
	Msg    []string `mapstructure:"msg"`
	Pkg    []string `mapstructure:"pkg"`
	File   []string `mapstructure:"file"`
	Level  []string `mapstructure:"level"`
	Regex  []string `mapstructure:"regex"`
	LibBPF bool     `mapstructure:"libbpf"`
}

// GetLoggerConfig returns the logger configuration.
func (l *LogConfig) GetLoggingConfig() logger.LoggingConfig {
	return logger.LoggingConfig{
		Logger:        logger.NewLogger(l.loggerCfg),
		LoggerConfig:  l.loggerCfg,
		Filter:        l.filter,
		Aggregate:     l.aggregate,
		FlushInterval: l.flushInterval,
	}
}

// flags returns the flags for the log configuration.
func (l *LogConfig) flags() []string {
	flags := []string{}

	// level
	if l.Level != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", level, l.Level))
	}

	// file
	if l.File != "" {
		flags = append(flags, fmt.Sprintf("%s=%s", file, l.File))
	}

	// aggregate
	if l.Aggregate.Enabled || l.Aggregate.FlushInterval != "" {
		flags = append(flags, aggregation)
	}
	if l.Aggregate.FlushInterval != "" {
		flags = append(flags, fmt.Sprintf("%s.%s=%s", aggregation, aggregationFlushInterval, l.Aggregate.FlushInterval))
	}

	// filters
	flags = append(flags, getLogFilterAttrFlags(filterInclude, l.Filters.Include)...)
	flags = append(flags, getLogFilterAttrFlags(filterExclude, l.Filters.Exclude)...)

	return flags
}

// getLogFilterAttrFlags returns the flags for the log filter attributes.
func getLogFilterAttrFlags(option string, attrs LogFilterAttributes) []string {
	attrFlags := []string{}

	// msg
	for _, msg := range attrs.Msg {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.msg=%s", filterKey, option, msg))
	}

	// pkg
	for _, pkg := range attrs.Pkg {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.pkg=%s", filterKey, option, pkg))
	}

	// file
	for _, file := range attrs.File {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.file=%s", filterKey, option, file))
	}

	// level
	for _, level := range attrs.Level {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.level=%s", filterKey, option, level))
	}

	// regex
	for _, regex := range attrs.Regex {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.regex=%s", filterKey, option, regex))
	}
	// libbpf
	if attrs.LibBPF {
		attrFlags = append(attrFlags, fmt.Sprintf("%s.%s.libbpf", filterKey, option))
	}

	return attrFlags
}

// PrepareLogger prepares the logger configuration from the log options.
func PrepareLogger(logOptions []string) (LogConfig, error) {
	var (
		agg           bool
		filter        = logger.NewLoggerFilter()
		flushInterval = logger.DefaultFlushInterval
		lvl           = logger.DefaultLevel
		err           error
		w             = os.Stderr
	)

	for _, opt := range logOptions {
		// Check if this is a level or file option first (they use "=" syntax)
		if strings.HasPrefix(opt, level+"=") || strings.HasPrefix(opt, file+"=") {
			// split by "=" for level and file options
			logParts := strings.SplitN(opt, "=", 2)
			if len(logParts) != 2 {
				return LogConfig{}, invalidLogOption(nil, opt)
			}

			switch logParts[0] {
			case level:
				lvl, err = parseLevel(logParts[1])
				if err != nil {
					return LogConfig{}, invalidLogOptionValue(err, opt)
				}
			case file:
				if logParts[1] == "" {
					return LogConfig{}, invalidLogOptionValue(nil, opt)
				}
				w, err = CreateOutputFile(logParts[1])
				if err != nil {
					return LogConfig{}, err
				}
			}
			continue
		}

		// Handle standalone "aggregate" option (without dot)
		if opt == aggregation {
			agg = true
			continue
		}

		// For other options, split by "." for filter and aggregation
		logParts := strings.SplitN(opt, ".", 2)
		if len(logParts) < 2 {
			return LogConfig{}, invalidLogOption(nil, opt)
		}

		switch logParts[0] {
		case aggregation:
			aggregationParts := strings.SplitN(logParts[1], "=", 2)

			switch aggregationParts[0] {
			case aggregationFlushInterval:
				agg = true // enable aggregation if flush-interval is set

				if len(aggregationParts) != 2 {
					return LogConfig{}, invalidLogOption(nil, opt)
				}

				if len(aggregationParts[1]) <= 1 {
					return LogConfig{}, invalidLogOptionValue(nil, opt)
				}

				// handle only seconds and minutes
				timeSuffix := aggregationParts[1][len(aggregationParts[1])-1:][0]
				if timeSuffix != 's' && timeSuffix != 'm' {
					return LogConfig{}, invalidLogOptionValue(nil, opt)
				}
				prevByte := aggregationParts[1][len(aggregationParts[1])-2:][0]
				if timeSuffix == 's' && !unicode.IsDigit(rune(prevByte)) {
					return LogConfig{}, invalidLogOptionValue(nil, opt)
				}

				flushInterval, err = time.ParseDuration(aggregationParts[1])
				if err != nil {
					return LogConfig{}, invalidLogOptionValue(nil, opt)
				}
			default:
				return LogConfig{}, invalidLogOption(nil, opt)
			}

		case filterKey:
			filterParts := strings.SplitN(logParts[1], ".", 2)
			if len(filterParts) != 2 {
				return LogConfig{}, invalidLogOption(nil, opt)
			}
			var filterKind logger.FilterKind
			switch filterParts[0] {
			case filterInclude:
				filterKind = logger.FilterIn
			case filterExclude:
				filterKind = logger.FilterOut
			default:
				return LogConfig{}, invalidLogOptionValue(nil, opt)
			}

			filterOpt := filterParts[1]
			if filterOpt == "" {
				return LogConfig{}, invalidLogOption(nil, opt)
			}

			err = processLogFilter(&filter, opt, filterKind, filterOpt)
			if err != nil {
				return LogConfig{}, err
			}
		default:
			return LogConfig{}, invalidLogOption(nil, opt)
		}
	}

	loggerCfg := logger.LoggerConfig{
		Writer: w,
		Level:  logger.NewAtomicLevelAt(lvl),
	}
	if lvl == logger.DebugLevel {
		loggerCfg.Encoder = logger.NewJSONEncoder(logger.NewDevelopmentEncoderConfig())
	} else {
		loggerCfg.Encoder = logger.NewJSONEncoder(logger.NewProductionEncoderConfig())
	}

	return LogConfig{
		loggerCfg:     loggerCfg,
		filter:        filter,
		aggregate:     agg,
		flushInterval: flushInterval,
	}, nil
}

// processLogFilter processes the log filter option.
func processLogFilter(filter *logger.LoggerFilter, opt string, filterKind logger.FilterKind, filterOpt string) error {
	optTypeParts := strings.SplitN(filterOpt, "=", 2)
	optType := optTypeParts[0]
	optVals := []string{}
	if len(optTypeParts) == 1 && optType != "libbpf" {
		return invalidLogOption(nil, opt)
	}
	if len(optTypeParts) == 2 {
		if optTypeParts[1] == "" {
			return invalidLogOptionValue(nil, opt)
		}
		optVals = strings.Split(optTypeParts[1], ",")
	}

	switch optType {
	case "msg":
		for _, val := range optVals {
			if err := filter.AddMsg(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "msg", val)
					continue
				}

				return invalidLogOption(err, opt)
			}
		}
	case "pkg":
		for _, val := range optVals {
			if err := filter.AddPkg(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "pkg", val)
					continue
				}

				return invalidLogOption(err, opt)
			}
		}
	case "file":
		for _, val := range optVals {
			if err := filter.AddFile(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "file", val)
					continue
				}

				return invalidLogOption(err, opt)
			}
		}
	case "level":
		for _, val := range optVals {
			filterLvl, err := parseLevel(val)
			if err != nil {
				return invalidLogOptionValue(err, opt)
			}

			if err := filter.AddLvl(int(filterLvl), filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "level", val)
					continue
				}

				return invalidLogOptionValue(err, opt)
			}
		}
	case "regex":
		for _, val := range optVals {
			if err := filter.AddMsgRegex(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "regex", val)
					continue
				}

				return invalidLogOption(err, opt)
			}
		}
	case "libbpf":
		if err := filter.AddMsgRegex("^libbpf:", filterKind); err != nil {
			if errors.Is(err, logger.ErrFilterOutExistsForKey) {
				logger.Warnw(err.Error(), "regex", "^libbpf:")
				return nil
			}
			return invalidLogOptionValue(err, opt)
		}
	default:
		return invalidLogOption(nil, opt)
	}
	return nil
}

// invalidLogOption returns an error for an invalid log option.
func invalidLogOption(err error, opt string) error {
	if err == nil {
		// this is a hack to clear the previous two chars from the error message
		err = errors.New("\b\b")
	}

	return errfmt.Errorf("invalid log option: %s, %s, run 'tracee man logging' for more info", opt, err)
}

// invalidLogOptionValue returns an error for an invalid log option value.
func invalidLogOptionValue(err error, opt string) error {
	if err == nil {
		// this is a hack to clear the previous two chars from the error message
		err = errors.New("\b\b")
	}

	return errfmt.Errorf("invalid log option value: %s, %s, use '--help' for more info", opt, err)
}

// parseLevel parses the log level.
func parseLevel(level string) (logger.Level, error) {
	switch level {
	case levelDebug:
		return logger.DebugLevel, nil
	case levelInfo:
		return logger.InfoLevel, nil
	case levelWarn:
		return logger.WarnLevel, nil
	case levelError:
		return logger.ErrorLevel, nil
	case levelFatal:
		return logger.FatalLevel, nil
	default:
		return logger.DebugLevel, errors.New("invalid log level")
	}
}
