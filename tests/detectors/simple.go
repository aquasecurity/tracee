package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// SimpleDetectorTest provides a lightweight way to test detectors
// without the full harness overhead. Perfect for unit tests of detector logic.
type SimpleDetectorTest struct {
	detector detection.EventDetector
	ctx      context.Context
	t        *testing.T
}

// NewSimpleTest creates a minimal detector test environment
// The detector is initialized with minimal dependencies (logger + empty config)
func NewSimpleTest(t *testing.T, detector detection.EventDetector) *SimpleDetectorTest {
	err := detector.Init(detection.DetectorParams{
		Logger: &testLogger{t: t},
		Config: detection.NewEmptyDetectorConfig(),
	})
	require.NoError(t, err, "Failed to initialize detector")

	return &SimpleDetectorTest{
		detector: detector,
		ctx:      context.Background(),
		t:        t,
	}
}

// SendEvent sends a single event and returns all outputs
func (s *SimpleDetectorTest) SendEvent(event *v1beta1.Event) []detection.DetectorOutput {
	outputs, err := s.detector.OnEvent(s.ctx, event)
	require.NoError(s.t, err, "OnEvent failed")
	return outputs
}

// SendStream sends multiple events in sequence and collects all outputs
// This is essential for testing stateful detectors that track patterns across events
func (s *SimpleDetectorTest) SendStream(events []*v1beta1.Event) []detection.DetectorOutput {
	var allOutputs []detection.DetectorOutput
	for i, event := range events {
		outputs, err := s.detector.OnEvent(s.ctx, event)
		require.NoError(s.t, err, "OnEvent failed at event index %d", i)
		allOutputs = append(allOutputs, outputs...)
	}
	return allOutputs
}

// ExpectOutput sends an event and asserts exactly one output is produced
func (s *SimpleDetectorTest) ExpectOutput(event *v1beta1.Event) *detection.DetectorOutput {
	outputs := s.SendEvent(event)
	require.Len(s.t, outputs, 1, "Expected exactly 1 output event")
	return &outputs[0]
}

// ExpectNoOutput sends an event and asserts no output is produced
func (s *SimpleDetectorTest) ExpectNoOutput(event *v1beta1.Event) {
	outputs := s.SendEvent(event)
	require.Empty(s.t, outputs, "Expected no output events")
}

// ExpectOutputCount sends an event and asserts a specific number of outputs
func (s *SimpleDetectorTest) ExpectOutputCount(event *v1beta1.Event, count int) []detection.DetectorOutput {
	outputs := s.SendEvent(event)
	require.Len(s.t, outputs, count, "Expected %d output events", count)
	return outputs
}

// Close cleans up detector resources
func (s *SimpleDetectorTest) Close() {
	if closer, ok := s.detector.(interface{ Close() }); ok {
		closer.Close()
	}
}
