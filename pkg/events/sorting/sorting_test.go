package sorting

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/types/trace"
)

type sortableEventsList struct {
	eventsList []trace.Event
}

func (e sortableEventsList) Len() int {
	return len(e.eventsList)
}

func (e sortableEventsList) Less(i, j int) bool {
	return e.eventsList[i].Timestamp < e.eventsList[j].Timestamp
}

func (e sortableEventsList) Swap(i, j int) {
	e.eventsList[i], e.eventsList[j] = e.eventsList[j], e.eventsList[i]
}

func TestEventsChronologicalSorter_addEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		events                []trace.Event
		expectedCpuQueuesLens map[int]int
		name                  string
	}{{
		events: []trace.Event{
			{ProcessorID: 0, Timestamp: 1},
			{ProcessorID: 0, Timestamp: 2},
			{ProcessorID: 0, Timestamp: 3},
		},
		expectedCpuQueuesLens: map[int]int{
			0: 3,
			1: 0,
		},
		name: "Sorting chronological order events from 1 CPU",
	},
		{
			events: []trace.Event{
				{ProcessorID: 0, Timestamp: 1},
				{ProcessorID: 1, Timestamp: 2},
				{ProcessorID: 0, Timestamp: 3},
			},
			expectedCpuQueuesLens: map[int]int{
				0: 2,
				1: 1,
			},
			name: "Sorting chronological order events from multiple CPUs",
		},
		{
			events: []trace.Event{
				{ProcessorID: 0, Timestamp: 2},
				{ProcessorID: 0, Timestamp: 3},
				{ProcessorID: 0, Timestamp: 4},
				{ProcessorID: 0, Timestamp: 5},
				{ProcessorID: 0, Timestamp: 1},
			},
			expectedCpuQueuesLens: map[int]int{
				0: 5,
				1: 0,
			},
			name: "Sorting not chronological order events from 1 CPU",
		},
		{
			events: []trace.Event{
				{ProcessorID: 0, Timestamp: 2},
				{ProcessorID: 0, Timestamp: 3},
				{ProcessorID: 1, Timestamp: 4},
				{ProcessorID: 1, Timestamp: 5},
				{ProcessorID: 1, Timestamp: 1},
			},
			expectedCpuQueuesLens: map[int]int{
				0: 2,
				1: 3,
			},
			name: "Sorting not chronological order events",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			errChan := make(chan error)
			newSorter, err := InitEventSorter()
			require.NoError(t, err)
			newSorter.cpuEventsQueues = make([]cpuEventsQueue, len(testCase.expectedCpuQueuesLens))
			require.NoError(t, err, testCase.name)
			for i := 0; i < len(testCase.events); i++ {
				newSorter.addEvent(&testCase.events[i])
			}
			assert.Empty(t, errChan)
			// need to use a pointer (instead of range) so mutexes aren't copied
			for cpuid := 0; cpuid < len(newSorter.cpuEventsQueues); cpuid++ {
				cpuEventsQueue := &newSorter.cpuEventsQueues[cpuid]
				require.Contains(t, testCase.expectedCpuQueuesLens, cpuid)
				eventsCounter := 0
				if cpuEventsQueue.head != nil {
					eventsCounter++
					for testEvent := cpuEventsQueue.head; testEvent.previous != nil; testEvent = testEvent.previous {
						require.NotEqual(t, testEvent, testEvent.previous) // Prevent infinite loops
						assert.True(t, testEvent.event.Timestamp < testEvent.previous.event.Timestamp)
						eventsCounter++
					}
				}
				assert.Equal(t, testCase.expectedCpuQueuesLens[cpuid], eventsCounter)
			}
		})
	}
}

type eventsIteration struct {
	events []trace.Event
	delay  time.Duration // Delay from last iteration
}

type sorterTestCase struct {
	eventsPools  []eventsIteration
	name         string
	eventsAmount int
	cpuAmount    int
}

func TestEventsChronologicalSorter_Start(t *testing.T) {
	t.Parallel()

	sendingInterval := 100 * time.Millisecond
	testCases := []sorterTestCase{
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 1},
						{ProcessorID: 0, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
					},
				},
			},
			name:         "Sorting chronological order events from 1 CPU",
			eventsAmount: 3,
			cpuAmount:    1,
		},
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 1},
						{ProcessorID: 1, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
					},
				},
			},
			name:         "Sorting chronological order events from multiple CPUs",
			eventsAmount: 3,
			cpuAmount:    2,
		},
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
						{ProcessorID: 0, Timestamp: 4},
						{ProcessorID: 0, Timestamp: 5},
						{ProcessorID: 0, Timestamp: 1},
					},
				},
			},
			name:         "Sorting not chronological order events from 1 CPU",
			eventsAmount: 5,
			cpuAmount:    1,
		},
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
						{ProcessorID: 1, Timestamp: 4},
						{ProcessorID: 1, Timestamp: 5},
						{ProcessorID: 1, Timestamp: 1},
					},
				},
			},
			name:         "Sorting not chronological order events from multiple CPUs",
			eventsAmount: 5,
			cpuAmount:    2,
		},
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
						{ProcessorID: 1, Timestamp: 4},
						{ProcessorID: 1, Timestamp: 5},
						{ProcessorID: 0, Timestamp: 7},
					},
				},
				{
					delay: sendingInterval - time.Millisecond,
					events: []trace.Event{
						{ProcessorID: 1, Timestamp: 10},
						{ProcessorID: 1, Timestamp: 11},
						{ProcessorID: 1, Timestamp: 6},
					},
				},
			},
			name:         "Sorting unsorted events after vCPU sleep",
			eventsAmount: 8,
			cpuAmount:    2,
		},
		{
			eventsPools:  []eventsIteration{},
			name:         "Sorting with no events",
			eventsAmount: 0,
			cpuAmount:    1,
		},
		{
			eventsPools: []eventsIteration{
				{
					delay: sendingInterval,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 1},
					},
				},
				{
					delay: 3 * sendingInterval,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 2},
					},
				},
				{
					delay: 3 * sendingInterval,
					events: []trace.Event{
						{ProcessorID: 0, Timestamp: 3},
					},
				},
			},
			name:         "Sorting chronological order events from 1 CPU low pace",
			eventsAmount: 3,
			cpuAmount:    1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			outputChan := make(chan *trace.Event)
			fatalErrorsChan := make(chan error)
			errChan := make(chan error)
			newSorter, err := InitEventSorter()
			require.NoError(t, err)
			newSorter.cpuEventsQueues = make([]cpuEventsQueue, testCase.cpuAmount)
			newSorter.eventsPassingInterval = sendingInterval // Make sure that interval high enough for test
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			inputChan := sendTestEvents(testCase.eventsPools)
			go newSorter.Start(inputChan, outputChan, ctx, fatalErrorsChan)
			outputList, sorterErr := retrieveEventsFromSorter(testCase.eventsAmount, outputChan, fatalErrorsChan)
			cancel()
			close(inputChan)
			require.NoError(t, sorterErr)
			assert.Empty(t, errChan)
			assert.True(t, sort.IsSorted(sortableEventsList{outputList}))
		})
	}
}

func retrieveEventsFromSorter(expectedEventsAmount int, sorterOutputChan <-chan *trace.Event, fatalErrorsChan chan error) ([]trace.Event, error) {
	ticker := time.NewTicker(2 * time.Second)
	outputList := make([]trace.Event, 0)
	eventsReceived := 0
	for {
		select {
		case event, ok := <-sorterOutputChan:
			if !ok {
				return outputList, nil
			}
			outputList = append(outputList, *event)
			eventsReceived++
			if eventsReceived > expectedEventsAmount {
				return outputList, fmt.Errorf("more events returned from sorter than expected")
			}
		case err := <-fatalErrorsChan:
			return nil, err
		case <-ticker.C:
			if eventsReceived != expectedEventsAmount {
				return nil, fmt.Errorf("not all events received until timeout")
			}
			return outputList, nil
		}
	}
}

func sendTestEvents(eventPool []eventsIteration) chan *trace.Event {
	inputChan := make(chan *trace.Event)
	go func() {
		startTime := int(time.Now().UnixNano())
		for _, eventsIteration := range eventPool {
			time.Sleep(eventsIteration.delay)
			for _, event := range eventsIteration.events {
				event := event
				event.Timestamp = startTime + (event.Timestamp * int(time.Millisecond.Nanoseconds()))
				inputChan <- &event
			}
		}
	}()
	return inputChan
}
