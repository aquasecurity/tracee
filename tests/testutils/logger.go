package testutils

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/common/logger"
)

// SetTestLogger create a logger which prints the logs to the returned channel.
// This function is meant to be used by tests to check logs, and by that test the
// flow of Tracee from outside.
func SetTestLogger(t *testing.T, l logger.Level) (loggerOutput <-chan []byte, restoreLogger func()) {
	t.Log("  --- setting test logger ---")

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
		t.Log("  --- restoring default logger ---")
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

// EnableTestLogger configures the logger to output directly to the test's log output.
// This is useful for debugging tests as all logger output will be visible in test results.
// Call the returned function to restore the original logger.
//
// Example usage:
//
//	func TestSomething(t *testing.T) {
//	    defer testutils.EnableTestLogger(t, logger.DebugLevel)()
//	    // ... your test code ...
//	}
func EnableTestLogger(t *testing.T, level logger.Level) func() {
	t.Helper()

	currentLogger := logger.GetLogger()
	testWriter := newTestWriter(t)

	testLogger := logger.NewLogger(
		logger.LoggerConfig{
			Writer:  testWriter,
			Level:   logger.NewAtomicLevelAt(level),
			Encoder: logger.NewConsoleEncoder(logger.NewDevelopmentEncoderConfig()),
		},
	)

	logger.SetLogger(testLogger)

	return func() {
		t.Helper()
		_ = testLogger.Sync()
		logger.SetLogger(currentLogger)
	}
}

// testWriter is an io.Writer that writes to testing.T's log output
type testWriter struct {
	t      *testing.T
	mu     sync.Mutex
	buffer bytes.Buffer
}

func newTestWriter(t *testing.T) *testWriter {
	return &testWriter{t: t}
}

// Write implements io.Writer. It buffers lines and logs them via testing.T
func (tw *testWriter) Write(p []byte) (n int, err error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Write to buffer
	n, err = tw.buffer.Write(p)
	if err != nil {
		return n, err
	}

	// Flush complete lines
	for {
		line, err := tw.buffer.ReadString('\n')
		if err != nil {
			// No complete line yet, put back what we read
			if line != "" {
				tw.buffer.WriteString(line)
			}
			break
		}
		// Log the line (without the trailing newline as t.Log adds its own)
		tw.t.Log(strings.TrimSuffix(line, "\n"))
	}

	return n, nil
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

	outChan := make(chan bool, 1)

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
		select {
		case outChan <- allFound:
			// sent successfully
		case <-time.After(10 * time.Second):
			t.Logf("Test %s failed: TestLogs: timeout sending result to outChan", t.Name())
		}
	}()
	return outChan
}
