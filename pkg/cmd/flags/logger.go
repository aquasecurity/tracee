package flags

import (
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
  --log aggregate[:interval]          | turns log aggregation on, delaying output optional interval (s, m) (default is off)
  --log <debug|info|warn|error|panic> | set log level, info is the default
  --log libbpfgo-filters-off          | disable libbpfgo callback filters (print all libbpf output)
  --log file:/path/to/file            | write the logs to a specified file. create/trim the file if exists (default: stderr)

Examples:
  --log debug                              | outputs debug level logs
  --log debug --log aggregate              | outputs aggregated debug level logs every 3 seconds (default)
  --log aggregate:5s                       | outputs aggregated logs every 5 seconds
  --log debug --log file:/tmp/tracee.log   | outputs debug level logs to /tmp/tracee.log
`
}

func InvalidLogOption(opt string) error {
	return errfmt.Errorf("invalid log option: %s, use '--log help' for more info", opt)
}

// PrepareLogger parses the log options returning a logger config,
// a boolean indicating if libbpfgo should filter libbpf logs and an error if any.
func PrepareLogger(logOptions []string) (*logger.LoggerConfig, bool, error) {
	var (
		w        = os.Stderr
		lvl      = logger.DefaultLevel
		agg      bool
		interval = logger.DefaultFlushInterval

		filterLibbpfgo = true // default is to filter libbpf logs
		err            error
	)

	for _, opt := range logOptions {

		if strings.HasPrefix(opt, "file") {
			vals := strings.Split(opt, ":")

			if len(vals) == 1 || vals[1] == "" {
				return nil, false, InvalidLogOption(opt)
			}

			w, err = createFile(vals[1])
			if err != nil {
				return nil, false, err
			}

			continue
		}

		// parse aggregate option
		if strings.HasPrefix(opt, "aggregate") {
			if !strings.HasSuffix(opt, "aggregate") {
				vals := strings.Split(opt, ":")
				if len(vals) != 2 || len(vals[1]) <= 1 {
					return nil, false, InvalidLogOption(opt)
				}

				// handle only seconds and minutes
				timeSuffix := vals[1][len(vals[1])-1:][0]
				if timeSuffix != 's' && timeSuffix != 'm' {
					return nil, false, InvalidLogOption(opt)
				}
				prevByte := vals[1][len(vals[1])-2:][0]
				if timeSuffix == 's' && !unicode.IsDigit(rune(prevByte)) {
					return nil, false, InvalidLogOption(opt)
				}

				interval, err = time.ParseDuration(vals[1])
				if err != nil {
					return nil, false, InvalidLogOption(opt)
				}
			}

			agg = true
			continue
		}

		// parse libbpfgo-filters-off option
		// this option is used to disable libbpfgo callback filters
		if opt == "libbpfgo-filters-off" {
			filterLibbpfgo = false
			continue
		}

		// levels
		switch opt {
		case "debug":
			lvl = logger.DebugLevel
		case "info":
			lvl = logger.InfoLevel
		case "warn":
			lvl = logger.WarnLevel
		case "error":
			lvl = logger.ErrorLevel
		case "fatal":
			lvl = logger.FatalLevel
		default:
			return nil, false, InvalidLogOption(opt)
		}
	}

	cfg := &logger.LoggerConfig{
		Writer:        w,
		Level:         lvl,
		Aggregate:     agg,
		FlushInterval: interval,
	}
	if lvl == logger.DebugLevel {
		cfg.Encoder = logger.NewJSONEncoder(logger.NewDevelopmentEncoderConfig())
	} else {
		cfg.Encoder = logger.NewJSONEncoder(logger.NewProductionEncoderConfig())
	}

	return cfg, filterLibbpfgo, nil
}
