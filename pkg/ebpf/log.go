package ebpf

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/metrics"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"io/ioutil"
	"os"
)

// ErrorChanWriter is a io.Writer implementation that writes to error channel, while updating program stats.
type ErrorChanWriter struct {
	c     chan<- error
	stats *metrics.Stats
}

func InitErrorChanWriter(c chan<- error, stats *metrics.Stats) ErrorChanWriter {
	return ErrorChanWriter{
		c:     c,
		stats: stats,
	}
}

func (ec ErrorChanWriter) Write(message []byte) (n int, err error) {
	ec.stats.ErrorCount.Increment()
	ec.c <- fmt.Errorf(string(message))
	return n, nil
}

// ConfigureLogger configure the errors created by tracee to be directed into the error channel, and normal
// logs to stderr.
// Notice that the logger log level must enable the log for it to be written.
// For example, if the followed log level is Error and above, Warnings won't be written to the errors channel.
func (t *Tracee) ConfigureLogger() {
	log.SetOutput(ioutil.Discard) // Send all logs to nowhere by default

	log.AddHook(&writer.Hook{
		Writer: InitErrorChanWriter(t.config.ChanErrors, &t.stats),
		LogLevels: []log.Level{
			log.WarnLevel,
			log.ErrorLevel,
			log.FatalLevel,
			log.PanicLevel,
		},
	})
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.TraceLevel,
			log.DebugLevel,
			log.InfoLevel,
		},
	})
}
