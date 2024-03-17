package producer_test

import (
	"io"
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/producer"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProducer struct {
	producedEvents []trace.Event
	currentEvent   int
	done           chan struct{}
}

func initMockTimeFixerProducer(eventsToProduce []trace.Event) *mockProducer {
	return &mockProducer{
		producedEvents: eventsToProduce,
	}
}

func (m *mockProducer) Produce() (trace.Event, error) {
	index := m.currentEvent
	m.currentEvent += 1
	if m.currentEvent == len(m.producedEvents) {
		m.done <- struct{}{}
	}
	if index >= len(m.producedEvents) {
		return trace.Event{}, io.EOF
	}
	return m.producedEvents[index], nil
}

func (m *mockProducer) Done() <-chan struct{} {
	return m.done
}

func TestTimeFixerProducer(t *testing.T) {
	testCases := []struct {
		name               string
		events             []trace.Event
		expectedTimestamps []int
	}{
		{
			name: "no init event",
			events: []trace.Event{
				{
					EventID:   int(events.SchedProcessExec),
					Timestamp: 1000,
				},
			},
			expectedTimestamps: []int{1000},
		},
		{
			name: "init event",
			events: []trace.Event{
				{
					EventID:   int(events.InitTraceeData),
					Timestamp: 1000,
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "boot_time",
								Type: "uint64",
							},
							Value: uint64(80),
						},
					},
				},
				{
					EventID:   int(events.SchedProcessExec),
					Timestamp: 1000,
				},
			},
			expectedTimestamps: []int{20, 20},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create a new TimeFixerProducer
			mockProcer := initMockTimeFixerProducer(testCase.events)
			tfixer := producer.InitTimeFixerProducer(mockProcer)

			for i := 0; ; i++ {
				// Check the produced events' timestamps
				event, err := tfixer.Produce()
				if err == io.EOF {
					assert.Equal(t, len(testCase.expectedTimestamps), i)
					break
				}
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedTimestamps[i], event.Timestamp)
				if event.Timestamp != testCase.expectedTimestamps[i] {
					t.Errorf("Expected timestamp %d, got %d", testCase.expectedTimestamps[i], event.Timestamp)
				}
			}
		})
	}
}
