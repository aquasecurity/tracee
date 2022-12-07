package flags

import (
	"fmt"
	"io"

	"github.com/aquasecurity/tracee/pkg/logger"
)

func logHelp() string {
	return `Control logger level priority.

Possible options:
  --log debug               | debug log level
  --log info                | information log level (default) 
  --log warn                | warning log level
  --log error               | error log level
  --log panic               | panic log level
`
}

func PrepareLogger(logLevel string, w io.Writer) error {
	var lvl logger.Level

	switch logLevel {
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
		return fmt.Errorf("invalid log level: %s, use '--log help' for more info", logLevel)
	}

	logger.SetLevel(lvl)
	logger.SetWriter(w)

	return nil
}
