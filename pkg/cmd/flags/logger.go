package flags

import (
	"errors"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

const (
	LogFlagShort                = "l"
	LogFlag                     = "log"
	LogLevel                    = "level"
	LogLevelDebug               = "debug"
	LogLevelInfo                = "info"
	LogLevelWarn                = "warn"
	LogLevelError               = "error"
	LogLevelFatal               = "fatal"
	LogFile                     = "file"
	LogFilter                   = "filters"
	LogFilterInclude            = "include"
	LogFilterExclude            = "exclude"
	LogFilterLibbpf             = "libbpf"
	LogAggregation              = "aggregate"
	LogAggregationEnabled       = "enabled"
	LogAggregationFlushInterval = "flush-interval"
	DefaultLogLevelFlag         = LogLevel + "=" + LogLevelInfo
)

func logHelp() string {
	return `Control logger options - aggregation and level priority.

Possible options:
  --log aggregate.enable            			    | turns log aggregation on
  --log aggregate.flush-interval    				| delaying output with an optional interval (s, m) (default: 3s)
  --log level=<debug|info|warn|error|fatal> 		| set log level, info is the default
  --log file=/path/to/file            				| write the logs to a specified file. create/trim the file if exists (default: stderr)
  --log filters.include.<option;...>          		| Filters in logs that match the specified option values.
  --log filters.exclude.<option;...>       			| Filters out logs that match the specified option values.

Filter options:
  msg=<value,...> 				       | Filters logs that message contains a value.
  regex=<value,...>                    | Filters logs that a regex matches the message.
  pkg=<value,...>                      | Filters logs that originate from a package.
  file=<value,...>                     | Filters logs that originate from a file.
  level=<value,...>                    | Filters logs that are of a specific level.
  libbpf		                       | Filters logs that originate from libbpf.

Examples:
  --log level=debug                                      		     | outputs debug level logs
  --log level=debug --log aggregate.enable=true                      | outputs aggregated debug level logs every 3 seconds (default)
  --log aggregate.flush-interval=5s                                  | outputs aggregated logs every 5 seconds
  --log level=debug --log file=/tmp/tracee.log            			 | outputs debug level logs to /tmp/tracee.log
  --log filters.include.msg=foo,bar --log filters.include.pkg=core  	 | Filters in logs that have either 'foo' or 'bar' in the message, and are from the 'core' packag.
  --log filters.exclude.msg=foo,bar --log filters.exclude.pkg=core  	 | Filters out logs that have either 'foo' or 'bar' in the message, and are from the 'core' package.
  --log filters.exclude.file=/pkg/cmd/flags/logger.go	 			 | Filters out logs that are from the '/pkg/cmd/flags/logger.go' file.
  --log filters.include.regex='^foo'                         		 | Filters in logs that messages match the regex '^foo'.
  --log filters.include.libbpf                              			 | Filters in logs that originate from libbpf.
  --log filters.exclude.libbpf                              			 | Filters out logs that originate from libbpf.
`
}

func invalidLogOption(err error, opt string, newBinary bool) error {
	if err == nil {
		// this is a hack to clear the previous two chars from the error message
		err = errors.New("\b\b")
	}

	if newBinary {
		return errfmt.Errorf("invalid log option: %s, %s, run 'man log' for more info", opt, err)
	}

	return InvalidLogOptionError(opt, err.Error())
}

func invalidLogOptionValue(err error, opt string, newBinary bool) error {
	if err == nil {
		// this is a hack to clear the previous two chars from the error message
		err = errors.New("\b\b")
	}

	if newBinary {
		return errfmt.Errorf("invalid log option value: %s, %s, use '--help' for more info", opt, err)
	}

	return InvalidLogOptionValueError(opt, err.Error())
}

func parseLevel(level string) (logger.Level, error) {
	switch level {
	case LogLevelDebug:
		return logger.DebugLevel, nil
	case LogLevelInfo:
		return logger.InfoLevel, nil
	case LogLevelWarn:
		return logger.WarnLevel, nil
	case LogLevelError:
		return logger.ErrorLevel, nil
	case LogLevelFatal:
		return logger.FatalLevel, nil
	default:
		return logger.DebugLevel, errors.New("invalid log level")
	}
}
func PrepareLogger(logOptions []string, newBinary bool) (logger.LoggingConfig, error) {
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
		if strings.HasPrefix(opt, LogLevel+"=") || strings.HasPrefix(opt, LogFile+"=") {
			// split by "=" for level and file options
			logParts := strings.SplitN(opt, "=", 2)
			if len(logParts) != 2 {
				return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
			}

			switch logParts[0] {
			case LogLevel:
				lvl, err = parseLevel(logParts[1])
				if err != nil {
					return logger.LoggingConfig{}, invalidLogOptionValue(err, opt, newBinary)
				}
			case LogFile:
				if logParts[1] == "" {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
				w, err = CreateOutputFile(logParts[1])
				if err != nil {
					return logger.LoggingConfig{}, err
				}
			}
			continue
		}

		// For other options, split by "." for filter and aggregation
		logParts := strings.SplitN(opt, ".", 2)
		if len(logParts) < 2 {
			return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
		}

		switch logParts[0] {
		case LogAggregation:
			aggregationParts := strings.SplitN(logParts[1], "=", 2)
			if len(aggregationParts) != 2 {
				return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
			}

			switch aggregationParts[0] {
			case LogAggregationFlushInterval:
				if len(aggregationParts[1]) <= 1 {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}

				// handle only seconds and minutes
				timeSuffix := aggregationParts[1][len(aggregationParts[1])-1:][0]
				if timeSuffix != 's' && timeSuffix != 'm' {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
				prevByte := aggregationParts[1][len(aggregationParts[1])-2:][0]
				if timeSuffix == 's' && !unicode.IsDigit(rune(prevByte)) {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}

				flushInterval, err = time.ParseDuration(aggregationParts[1])
				if err != nil {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
				agg = true

			case LogAggregationEnabled:
				if aggregationParts[1] == "true" {
					agg = true
				} else if aggregationParts[1] != "false" {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
			default:
				return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
			}

		case LogFilter:
			filterParts := strings.SplitN(logParts[1], ".", 2)
			if len(filterParts) != 2 {
				return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
			}
			var filterKind logger.FilterKind
			switch filterParts[0] {
			case LogFilterInclude:
				filterKind = logger.FilterIn
			case LogFilterExclude:
				filterKind = logger.FilterOut
			default:
				return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
			}

			filterOpt := filterParts[1]
			if filterOpt == "" {
				return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
			}

			err = processLogFilter(&filter, opt, newBinary, filterKind, filterOpt)
			if err != nil {
				return logger.LoggingConfig{}, err
			}
		default:
			return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
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

	return logger.LoggingConfig{
		Logger:        logger.NewLogger(loggerCfg),
		LoggerConfig:  loggerCfg,
		Filter:        filter,
		Aggregate:     agg,
		FlushInterval: flushInterval,
	}, nil
}

func processLogFilter(filter *logger.LoggerFilter, opt string, newBinary bool, filterKind logger.FilterKind, filterOpt string) error {
	optTypeParts := strings.SplitN(filterOpt, "=", 2)
	optType := optTypeParts[0]
	optVals := []string{}
	if len(optTypeParts) == 1 && optType != "libbpf" {
		return invalidLogOption(nil, opt, newBinary)
	}
	if len(optTypeParts) == 2 {
		if optTypeParts[1] == "" {
			return invalidLogOptionValue(nil, opt, newBinary)
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

				return invalidLogOption(err, opt, newBinary)
			}
		}
	case "pkg":
		for _, val := range optVals {
			if err := filter.AddPkg(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "pkg", val)
					continue
				}

				return invalidLogOption(err, opt, newBinary)
			}
		}
	case "file":
		for _, val := range optVals {
			if err := filter.AddFile(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "file", val)
					continue
				}

				return invalidLogOption(err, opt, newBinary)
			}
		}
	case "level":
		for _, val := range optVals {
			filterLvl, err := parseLevel(val)
			if err != nil {
				return invalidLogOptionValue(err, opt, newBinary)
			}

			if err := filter.AddLvl(int(filterLvl), filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "level", val)
					continue
				}

				return invalidLogOptionValue(err, opt, newBinary)
			}
		}
	case "regex":
		for _, val := range optVals {
			if err := filter.AddMsgRegex(val, filterKind); err != nil {
				if errors.Is(err, logger.ErrFilterOutExistsForKey) {
					logger.Warnw(err.Error(), "regex", val)
					continue
				}

				return invalidLogOptionValue(err, opt, newBinary)
			}
		}
	case "libbpf":
		if err := filter.AddMsgRegex("^libbpf:", filterKind); err != nil {
			if errors.Is(err, logger.ErrFilterOutExistsForKey) {
				logger.Warnw(err.Error(), "regex", "^libbpf:")
				return nil
			}
			return invalidLogOptionValue(err, opt, newBinary)
		}
	default:
		return invalidLogOption(nil, opt, newBinary)
	}
	return nil
}
