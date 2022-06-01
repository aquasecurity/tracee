package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/metrics"
)

// TraceeLogger is a logger for tracee-ebpf, to pass errors according to configuration.
type TraceeLogger struct {
	isDebug   bool
	stats     *metrics.Stats
	errorChan chan<- error
}

func InitTraceeLogger(isDebug bool, stats *metrics.Stats, errChan chan<- error) TraceeLogger {
	return TraceeLogger{
		isDebug:   isDebug,
		stats:     stats,
		errorChan: errChan,
	}
}

func (tl TraceeLogger) Error(err string) {
	tl.stats.ErrorCount.Increment()
	tl.errorChan <- fmt.Errorf(err)
}

func (tl TraceeLogger) Warning(err string) {
	if tl.isDebug {
		tl.Error(err)
	}
}

func (tl TraceeLogger) Info(message string) {
	fmt.Println(message)
}

func (tl TraceeLogger) Debug(message string) {
	if tl.isDebug {
		fmt.Println(message)
	}
}
