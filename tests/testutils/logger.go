package testutils

import (
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// SetTestLogger create a logger which prints the logs to the returned channel.
// This function is meant to be used by tests to check logs, and by that test the
// flow of Tracee from outside.
func SetTestLogger(t *testing.T, l logger.Level) (loggerOutput <-chan []byte, restoreLogger func()) {
	t.Logf("  --- setting test logger ---")

	mw, logChan := newChannelWriter()
	chanLogger := logger.NewLogger(
		logger.LoggerConfig{
			Writer:  mw,
			Level:   logger.NewAtomicLevelAt(l),
			Encoder: logger.NewJSONEncoder(logger.NewProductionConfig().EncoderConfig),
		},
	)
	currentLogger := logger.GetLogger()
	restoreLogger = func() {
		t.Logf("  --- restoring default logger ---")
		err := chanLogger.Sync()
		logger.SetLogger(currentLogger)
		mw.Close()
		if err != nil {
			logger.Errorw("Logger sync error", "error", err)
		}
	}
	logger.SetLogger(chanLogger)
	return logChan, restoreLogger
}

// channelWriter is an io.WriterCloser implementation that writes into a channel.
// It is implemented in a thread-safe manner, which shouldn't cause races.
type channelWriter struct {
	wg     sync.WaitGroup
	finish bool
	Out    chan<- []byte
}

func newChannelWriter() (*channelWriter, <-chan []byte) {
	outChan := make(chan []byte, 100)
	writer := channelWriter{Out: outChan}
	return &writer, outChan
}

func (cw *channelWriter) Write(p []byte) (n int, err error) {
	if cw.finish {
		return 0, io.ErrClosedPipe
	}
	cw.wg.Add(1)
	defer cw.wg.Done()
	if cw.finish {
		return 0, io.ErrClosedPipe
	}
	cw.Out <- slices.Clone(p)
	return len(p), nil
}

func (cw *channelWriter) Close() {
	cw.finish = true
	cw.wg.Wait()
	close(cw.Out)
}

// TestLogs searches for the given logs and test when input channel closes if all
// logs were received.
// It also returns a channel with the result of the test - whether all logs were found.
func TestLogs(
	t *testing.T,
	logsToSearch []string,
	logsChan <-chan []byte,
	done <-chan struct{},
) <-chan bool {
	testResults := make(map[string]bool, len(logsToSearch))
	for _, log := range logsToSearch {
		testResults[log] = false
	}

	outChan := make(chan bool)

	go func() {
		defer close(outChan)
	Loop:
		for {
			select {
			case receivedLog, ok := <-logsChan:
				if !ok {
					break Loop
				}
				for _, logToSearch := range logsToSearch {
					if strings.Contains(string(receivedLog), logToSearch) {
						testResults[logToSearch] = true
					}
				}
			case <-done:
				break Loop
			}
		}

		allFound := true
		for logToSearch, found := range testResults {
			assert.True(t, found, logToSearch)
			if !found {
				allFound = false
			}
		}
		outChan <- allFound
	}()
	return outChan
}
