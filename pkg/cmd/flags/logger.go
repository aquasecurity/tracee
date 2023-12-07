package flags

import (
	"errors"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func logHelp() string {
	return `Control logger options - aggregation and level priority.

Possible options:
  --log aggregate[:flush-interval]    | turns log aggregation on, delaying output with an optional interval (s, m) (default: 3s)
  --log <debug|info|warn|error|panic> | set log level, info is the default
  --log file:/path/to/file            | write the logs to a specified file. create/trim the file if exists (default: stderr)
  --log filter:<option;...>           | Filters in logs that match the specified option values.
  --log filter-out:<option;...>       | Filters out logs that match the specified option values.

Filter options:
  msg=<value,...> 				       | Filters logs that message contains a value.
  regex=<value,...>                    | Filters logs that a regex matches the message.
  pkg=<value,...>                      | Filters logs that originate from a package.
  file=<value,...>                     | Filters logs that originate from a file.
  lvl=<value,...>                      | Filters logs that are of a specific level.
  libbpf                               | Filters logs that originate from libbpf.

Examples:
  --log debug                                        | outputs debug level logs
  --log debug --log aggregate                        | outputs aggregated debug level logs every 3 seconds (default)
  --log aggregate:5s                                 | outputs aggregated logs every 5 seconds
  --log debug --log file:/tmp/tracee.log             | outputs debug level logs to /tmp/tracee.log
  --log filter:'msg=foo,bar;pkg=core;lvl=error'      | Filters in logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level.
  --log filter-out:'msg=foo,bar;pkg=core;lvl=error'  | Filters out logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level.
  --log filter:msg=foo,bar --log filter-out:pkg=core | Filters in logs that have either 'foo' or 'bar' in the message, and based on that result, filters out logs that are from the 'core' package.
  --log filter-out:file=/pkg/cmd/flags/logger.go	 | Filters out logs that are from the '/pkg/cmd/flags/logger.go' file.
  --log filter:regex='^foo'                          | Filters in logs that messages match the regex '^foo'.
  --log filter:libbpf                                | Filters in logs that originate from libbpf.
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

	return errfmt.Errorf("invalid log option: %s, %s, use '--log help' for more info", opt, err)
}

func invalidLogOptionValue(err error, opt string, newBinary bool) error {
	if err == nil {
		// this is a hack to clear the previous two chars from the error message
		err = errors.New("\b\b")
	}

	if newBinary {
		return errfmt.Errorf("invalid log option value: %s, %s, use '--help' for more info", opt, err)
	}

	return errfmt.Errorf("invalid log option value: %s, %s, use '--log help' for more info", opt, err)
}

func parseLevel(level string) (logger.Level, error) {
	switch level {
	case "debug":
		return logger.DebugLevel, nil
	case "info":
		return logger.InfoLevel, nil
	case "warn":
		return logger.WarnLevel, nil
	case "error":
		return logger.ErrorLevel, nil
	case "fatal":
		return logger.FatalLevel, nil
	default:
		return logger.DebugLevel, errors.New("invalid log level")
	}
}

func validateLogOption(opt string) error {
	switch {
	case strings.HasPrefix(opt, "file"):
		return nil
	case strings.HasPrefix(opt, "aggregate"):
		return nil
	case strings.HasPrefix(opt, "filter-out"):
		return nil
	case strings.HasPrefix(opt, "filter"):
		return nil
	}

	if _, err := parseLevel(opt); err == nil {
		return nil
	}

	// don't pass the error, it's not relevant in this case
	return invalidLogOption(nil, opt, false)
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
		if err := validateLogOption(opt); err != nil {
			return logger.LoggingConfig{}, err
		}

		// parse file option
		if strings.HasPrefix(opt, "file") {
			vals := strings.Split(opt, ":")

			if len(vals) == 1 || vals[1] == "" {
				return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
			}

			w, err = createFile(vals[1])
			if err != nil {
				return logger.LoggingConfig{}, err
			}

			continue
		}

		// parse aggregate option
		if strings.HasPrefix(opt, "aggregate") {
			if !strings.HasSuffix(opt, "aggregate") {
				vals := strings.Split(opt, ":")
				if len(vals) != 2 || len(vals[1]) <= 1 {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}

				// handle only seconds and minutes
				timeSuffix := vals[1][len(vals[1])-1:][0]
				if timeSuffix != 's' && timeSuffix != 'm' {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
				prevByte := vals[1][len(vals[1])-2:][0]
				if timeSuffix == 's' && !unicode.IsDigit(rune(prevByte)) {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}

				flushInterval, err = time.ParseDuration(vals[1])
				if err != nil {
					return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
				}
			}

			agg = true
			continue
		}

		// parse filter option
		filterOpts := ""
		var filterKind logger.FilterKind
		if strings.HasPrefix(opt, "filter-out:") {
			filterOpts = strings.TrimPrefix(opt, "filter-out:")
			filterKind = logger.FilterOut
		} else if strings.HasPrefix(opt, "filter:") {
			filterOpts = strings.TrimPrefix(opt, "filter:")
			filterKind = logger.FilterIn
		}
		if filterOpts != "" {
			for _, filterOpt := range strings.Split(filterOpts, ";") {
				optTypeVal := strings.SplitN(filterOpt, "=", 2)
				optType := optTypeVal[0]
				optVals := []string{}
				if len(optTypeVal) == 1 && optType != "libbpf" {
					return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
				}
				if len(optTypeVal) == 2 {
					if optTypeVal[1] == "" {
						return logger.LoggingConfig{}, invalidLogOptionValue(nil, opt, newBinary)
					}
					optVals = strings.Split(optTypeVal[1], ",")
				}

				switch optType {
				case "msg":
					for _, val := range optVals {
						if err := filter.AddMsg(val, filterKind); err != nil {
							if errors.Is(err, logger.ErrFilterOutExistsForKey) {
								logger.Warnw(err.Error(), "msg", val)
								continue
							}

							return logger.LoggingConfig{}, invalidLogOption(err, opt, newBinary)
						}
					}
				case "pkg":
					for _, val := range optVals {
						if err := filter.AddPkg(val, filterKind); err != nil {
							if errors.Is(err, logger.ErrFilterOutExistsForKey) {
								logger.Warnw(err.Error(), "pkg", val)
								continue
							}

							return logger.LoggingConfig{}, invalidLogOption(err, opt, newBinary)
						}
					}
				case "file":
					for _, val := range optVals {
						if err := filter.AddFile(val, filterKind); err != nil {
							if errors.Is(err, logger.ErrFilterOutExistsForKey) {
								logger.Warnw(err.Error(), "file", val)
								continue
							}

							return logger.LoggingConfig{}, invalidLogOption(err, opt, newBinary)
						}
					}
				case "lvl":
					for _, val := range optVals {
						filterLvl, err := parseLevel(val)
						if err != nil {
							return logger.LoggingConfig{}, invalidLogOptionValue(err, opt, newBinary)
						}

						if err := filter.AddLvl(int(filterLvl), filterKind); err != nil {
							if errors.Is(err, logger.ErrFilterOutExistsForKey) {
								logger.Warnw(err.Error(), "lvl", val)
								continue
							}

							return logger.LoggingConfig{}, invalidLogOptionValue(err, opt, newBinary)
						}
					}
				case "regex":
					for _, val := range optVals {
						if err := filter.AddMsgRegex(val, filterKind); err != nil {
							if errors.Is(err, logger.ErrFilterOutExistsForKey) {
								logger.Warnw(err.Error(), "regex", val)
								continue
							}

							return logger.LoggingConfig{}, invalidLogOptionValue(err, opt, newBinary)
						}
					}
				case "libbpf":
					if err := filter.AddMsgRegex("^libbpf:", filterKind); err != nil {
						if errors.Is(err, logger.ErrFilterOutExistsForKey) {
							logger.Warnw(err.Error(), "regex", "^libbpf:")
							continue
						}

						return logger.LoggingConfig{}, invalidLogOptionValue(err, opt, newBinary)
					}
				default:
					return logger.LoggingConfig{}, invalidLogOption(nil, opt, newBinary)
				}
			}
			continue
		}

		// parse level option
		lvl, err = parseLevel(opt)
		if err != nil {
			return logger.LoggingConfig{}, invalidLogOption(err, opt, newBinary)
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

	llogger := logger.NewLogger(loggerCfg)
	return logger.LoggingConfig{
		Logger:        llogger,
		LoggerConfig:  loggerCfg,
		Filter:        filter,
		Aggregate:     agg,
		FlushInterval: flushInterval,
	}, nil
}
