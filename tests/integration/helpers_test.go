package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// eventBuffer is a thread-safe buffer for storing events during testing
type eventBuffer struct {
	sync.RWMutex
	events []trace.Event
}

func newEventBuffer() *eventBuffer {
	return &eventBuffer{
		events: make([]trace.Event, 0),
	}
}

func (b *eventBuffer) addEvent(event trace.Event) {
	b.Lock()
	defer b.Unlock()
	b.events = append(b.events, event)
}

func (b *eventBuffer) getCopy() []trace.Event {
	b.RLock()
	defer b.RUnlock()
	eventsCopy := make([]trace.Event, len(b.events))
	copy(eventsCopy, b.events)
	return eventsCopy
}

// assureIsRoot ensures the test is running as root
func assureIsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}
}

// startTracee initializes and starts a Tracee instance with the given configuration
func startTracee(ctx context.Context, t *testing.T, cfg config.Config, eventChan chan trace.Event, errChan chan error) (*events.EventProcessor, error) {
	// TODO: Initialize and start Tracee with the given configuration
	// This is a placeholder that needs to be implemented based on the actual Tracee initialization logic
	return nil, nil
}

// waitForTraceeStart waits for Tracee to fully initialize
func waitForTraceeStart(tracee *events.EventProcessor) error {
	// TODO: Implement proper wait logic for Tracee initialization
	time.Sleep(2 * time.Second)
	return nil
}

// waitForTraceeOutputEvents waits for events to be captured
func waitForTraceeOutputEvents(t *testing.T, timeout time.Duration, buffer *eventBuffer, minEvents int, allowTimeout bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if len(buffer.getCopy()) >= minEvents {
			return nil
		}
		if time.Now().After(deadline) {
			if allowTimeout {
				return nil
			}
			return fmt.Errorf("timeout waiting for events")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
