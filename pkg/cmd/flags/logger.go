package flags

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/aquasecurity/tracee/pkg/logger"
)

func logHelp() string {
	return `Control logger options - aggregation and level priority.

Possible options:
  --log aggregate                | turns log aggregation on, delaying output (default is off)
  --log aggregate:interval       | turns log aggregation on, delaying output to every 'interval' (s, m)
  --log debug                    | debug log level
  --log info                     | information log level (default)
  --log warn                     | warning log level
  --log error                    | error log level
  --log panic                    | panic log level

Examples:
  --log debug                    | outputs debug level logs
  --log debug --log aggregate    | outputs aggregated debug level logs every 3 seconds (default)
  --log aggregate:5s             | outputs aggregated logs every 5 seconds
`
}

func InvalidLogOption(opt string) error {
	return fmt.Errorf("invalid log option: %s, use '--log help' for more info", opt)
}

func PrepareLogger(logOptions []string, w io.Writer) (*logger.LoggerConfig, error) {
	var (
		agg      bool
		interval = logger.DefaultFlushInterval
		lvl      = logger.DefaultLevel
		err      error
	)

	for _, opt := range logOptions {
		// parse aggregate option
		if strings.HasPrefix(opt, "aggregate") {
			if !strings.HasSuffix(opt, "aggregate") {
				vals := strings.Split(opt, ":")
				if len(vals) != 2 || len(vals[1]) <= 1 {
					return nil, InvalidLogOption(opt)
				}

				// handle only seconds and minutes
				timeSuffix := vals[1][len(vals[1])-1:][0]
				if timeSuffix != 's' && timeSuffix != 'm' {
					return nil, InvalidLogOption(opt)
				}
				prevByte := vals[1][len(vals[1])-2:][0]
				if timeSuffix == 's' && !unicode.IsDigit(rune(prevByte)) {
					return nil, InvalidLogOption(opt)
				}

				interval, err = time.ParseDuration(vals[1])
				if err != nil {
					return nil, InvalidLogOption(opt)
				}
			}
			agg = true
			continue
		}

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
			return nil, InvalidLogOption(opt)
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

	return cfg, nil
}
