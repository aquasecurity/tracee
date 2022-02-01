package sorting

import (
	"fmt"
	"golang.org/x/net/context"
	"sort"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sortableEventsList struct {
	eventsList []external.Event
}

func (e sortableEventsList) Len() int {
	return len(e.eventsList)
}

func (e sortableEventsList) Less(i, j int) bool {
	return e.eventsList[i].Timestamp < e.eventsList[j].Timestamp
}

func (e sortableEventsList) Swap(i, j int) {
	return
}

func TestEventsChronologicalSorter_addEvent(t *testing.T) {
	testCases := []struct {
		events                []external.Event
		expectedCpuQueuesLens map[int]int
		name                  string
	}{{
		events: []external.Event{
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
			events: []external.Event{
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
			events: []external.Event{
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
			events: []external.Event{
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
		t.Run(testCase.name, func(t *testing.T) {
			errChan := make(chan error)
			newSorter, err := InitEventSorter()
			require.NoError(t, err)
			newSorter.cpuEventsQueues = make([]cpuEventsQueue, len(testCase.expectedCpuQueuesLens))
			require.NoError(t, err, testCase.name)
			for i := 0; i < len(testCase.events); i++ {
				newSorter.addEvent(&testCase.events[i])
			}
			assert.Empty(t, errChan)
			for cpuid, cpuEventsQueue := range newSorter.cpuEventsQueues {
				require.Contains(t, testCase.expectedCpuQueuesLens, cpuid)
				eventsCounter := 0
				if cpuEventsQueue.head != nil {
					eventsCounter += 1
					for testEvent := cpuEventsQueue.head; testEvent.previous != nil; testEvent = testEvent.previous {
						require.NotEqual(t, testEvent, testEvent.previous) // Prevent infinite loops
						assert.True(t, testEvent.event.Timestamp < testEvent.previous.event.Timestamp)
						eventsCounter += 1
					}
				}
				assert.Equal(t, testCase.expectedCpuQueuesLens[cpuid], eventsCounter)
			}
		})

	}
}

type eventsIteration struct {
	events []external.Event
	delay  time.Duration // Delay from last iteration
}

type sorterTestCase struct {
	eventsPools  []eventsIteration
	name         string
	eventsAmount int
	cpuAmount    int
}

func TestEventsChronologicalSorter_Start(t *testing.T) {
	testCases := []sorterTestCase{
		{
			eventsPools: []eventsIteration{
				{
					delay: 0,
					events: []external.Event{
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
					events: []external.Event{
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
					events: []external.Event{
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
					events: []external.Event{
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
					events: []external.Event{
						{ProcessorID: 0, Timestamp: 2},
						{ProcessorID: 0, Timestamp: 3},
						{ProcessorID: 1, Timestamp: 4},
						{ProcessorID: 1, Timestamp: 5},
						{ProcessorID: 0, Timestamp: 7},
					},
				},
				{
					delay: minDelay - time.Millisecond,
					events: []external.Event{
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
					delay: 100 * time.Millisecond,
					events: []external.Event{
						{ProcessorID: 0, Timestamp: 1},
					},
				},
				{
					delay: 300 * time.Millisecond,
					events: []external.Event{
						{ProcessorID: 0, Timestamp: 2},
					},
				},
				{
					delay: 300 * time.Millisecond,
					events: []external.Event{
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
		t.Run(testCase.name, func(t *testing.T) {
			inputChan := make(chan *external.Event, 100)
			outputChan := make(chan *external.Event, 100)
			fatalErrorsChan := make(chan error)
			errChan := make(chan error)
			newSorter, err := InitEventSorter()
			require.NoError(t, err)
			newSorter.cpuEventsQueues = make([]cpuEventsQueue, testCase.cpuAmount)
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			go newSorter.Start(inputChan, outputChan, ctx, fatalErrorsChan)
			go sendTestEvents(inputChan, testCase.eventsPools)
			outputList, sorterErr := retrieveEventsFromSorter(testCase.eventsAmount, outputChan, fatalErrorsChan)
			cancel()
			require.NoError(t, sorterErr)
			assert.Empty(t, errChan)
			assert.True(t, sort.IsSorted(sortableEventsList{outputList}))
		})
	}
}

func retrieveEventsFromSorter(expectedEventsAmount int, sorterOutputChan chan *external.Event, fatalErrorsChan chan error) ([]external.Event, error) {
	ticker := time.NewTicker(time.Second)
	outputList := make([]external.Event, 0)
	eventsReceived := 0
	for {
		select {
		case event := <-sorterOutputChan:
			outputList = append(outputList, *event)
			eventsReceived += 1
			if eventsReceived > expectedEventsAmount {
				return outputList, fmt.Errorf("more events returned from sorter than expected")
			}
		case err := <-fatalErrorsChan:
			return nil, err
		case <-ticker.C:
			if eventsReceived != expectedEventsAmount {
				return nil, fmt.Errorf("not all events received until timeout")
			} else {
				return outputList, nil
			}
		}
	}
}

func sendTestEvents(sorterInputChannel chan *external.Event, eventPool []eventsIteration) {
	startTime := int(time.Now().UnixNano())
	for _, eventsIteration := range eventPool {
		time.Sleep(eventsIteration.delay)
		for _, event := range eventsIteration.events {
			event.Timestamp = startTime + (event.Timestamp * int(time.Millisecond.Nanoseconds()))
			sorterInputChannel <- &event
		}
	}
}
