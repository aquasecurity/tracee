package examples

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/tests/detectors"
)

// TestStatefulDetectorStream demonstrates testing a stateful detector
// that tracks patterns across multiple events
func TestStatefulDetectorStream(t *testing.T) {
	detector := &BruteForceDetector{threshold: 3}
	test := detectors.NewSimpleTest(t, detector)
	defer test.Close()

	// Create stream of failed login attempts
	events := []*v1beta1.Event{
		createLoginEvent("192.168.1.100", false), // failed
		createLoginEvent("192.168.1.100", false), // failed
		createLoginEvent("192.168.1.100", false), // failed - should trigger
	}

	// Send stream and collect outputs
	outputs := test.SendStream(events)

	// Should fire once after threshold is reached
	assert.Len(t, outputs, 1)
	detectors.AssertFieldValue(t, outputs[0].Data, "source_ip", "192.168.1.100")
	detectors.AssertFieldValue(t, outputs[0].Data, "attempt_count", int32(3))
}

// TestStatefulDetectorNoTrigger demonstrates testing that state doesn't trigger prematurely
func TestStatefulDetectorNoTrigger(t *testing.T) {
	detector := &BruteForceDetector{threshold: 5}
	test := detectors.NewSimpleTest(t, detector)
	defer test.Close()

	// Send fewer events than threshold
	events := []*v1beta1.Event{
		createLoginEvent("192.168.1.100", false),
		createLoginEvent("192.168.1.100", false),
		createLoginEvent("192.168.1.100", false),
	}

	outputs := test.SendStream(events)
	assert.Empty(t, outputs, "Should not trigger before threshold")
}

// TestStatefulDetectorReset demonstrates testing state reset on success
func TestStatefulDetectorReset(t *testing.T) {
	detector := &BruteForceDetector{threshold: 3}
	test := detectors.NewSimpleTest(t, detector)
	defer test.Close()

	// Two failed attempts, then success (should reset), then two more failed
	events := []*v1beta1.Event{
		createLoginEvent("192.168.1.100", false),
		createLoginEvent("192.168.1.100", false),
		createLoginEvent("192.168.1.100", true), // success - resets counter
		createLoginEvent("192.168.1.100", false),
		createLoginEvent("192.168.1.100", false),
	}

	outputs := test.SendStream(events)
	assert.Empty(t, outputs, "Counter should reset on successful login")
}

// Helper to create login events
func createLoginEvent(sourceIP string, success bool) *v1beta1.Event {
	return &v1beta1.Event{
		Name: "security_login",
		Data: []*v1beta1.EventValue{
			{Name: "source_ip", Value: &v1beta1.EventValue_Str{Str: sourceIP}},
			{Name: "success", Value: &v1beta1.EventValue_Bool{Bool: success}},
		},
	}
}

// BruteForceDetector is a stateful detector example
type BruteForceDetector struct {
	threshold int
	mu        sync.Mutex
	attempts  map[string]int // IP -> attempt count
}

func (d *BruteForceDetector) Init(params detection.DetectorParams) error {
	d.attempts = make(map[string]int)
	return nil
}

func (d *BruteForceDetector) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "brute-force-example",
		ProducedEvent: v1beta1.EventDefinition{
			Name:    "brute_force_detected",
			Version: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
			Fields: []*v1beta1.EventField{
				{Name: "source_ip", Type: "string"},
				{Name: "attempt_count", Type: "int"},
			},
		},
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "security_login"},
			},
		},
	}
}

func (d *BruteForceDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract fields
	var sourceIP string
	var success bool
	for _, field := range event.Data {
		if field.Name == "source_ip" {
			sourceIP = field.GetStr()
		}
		if field.Name == "success" {
			success = field.GetBool()
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if success {
		// Reset counter on successful login
		delete(d.attempts, sourceIP)
		return nil, nil
	}

	// Increment failed attempts
	d.attempts[sourceIP]++

	// Check threshold
	if d.attempts[sourceIP] >= d.threshold {
		count := d.attempts[sourceIP]
		delete(d.attempts, sourceIP) // Reset after detection

		return []detection.DetectorOutput{{
			Data: []*v1beta1.EventValue{
				{Name: "source_ip", Value: &v1beta1.EventValue_Str{Str: sourceIP}},
				{Name: "attempt_count", Value: &v1beta1.EventValue_Int32{Int32: int32(count)}},
			},
		}}, nil
	}

	return nil, nil
}

func (d *BruteForceDetector) Close() {}
