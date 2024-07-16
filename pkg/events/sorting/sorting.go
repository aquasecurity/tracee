// Package sorting is responsible for sorting incoming events from the BPF programs chronologically.
//
// There are 3 known sources to events sorting issues:
//  1. In perf buffer, events are read in round robing order from CPUs buffers (and not according to invocation time).
//  2. Syscall events are invoked after internal events of the syscall (though the syscall happened before the
//     internal events).
//  3. Virtual CPUs might enter sleep mode by host machine scheduler and send events after some delay.
//
// To address the events perf buffers issue, the events are divided to queues according to the source CPU. This way
// the events are almost ordered (except for syscalls). The syscall events are inserted to their right chronological
// place manually.
// This way, all events which occurred before the last event of the most delaying CPU could be sent forward with
// guaranteed order.
// To make sure syscall events are not missed when sending, a small delay is needed.
// Lastly, to address the vCPU sleep issue (which might cause up to 2 events received in a delay), the events need to be
// sent after a delay which is bigger than max possible vCPU sleep time (which is just an increase of the syscall events
// delay sending).
//
// To summarize the algorithm main logic, here is textual simulation of the operation (assume that 2 scheduler ticks
// are larger than max possible vCPU sleep time):
//
//	-------------------------------------------------------------------
//
// Tn = Timestamp (n == TOD)
// #m = Event's Source CPU
//
// ### Initial State
//
//	     [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
//	HEAD    T1           T2           T4
//	        T3           T5
//	        T6
//	TAIL    T8
//
// ### Scheduler Tick #1
//
// Incoming events: T9#1, T11#2, T13#1, T10#2, T12#2
//
// Queues state after insert:
//
//	     [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
//	HEAD    T1           T2           T4
//	        T3           T5           T10 +
//	        T6           T9  +        T11 +
//	TAIL    T8           T13 +        T12 +
//
//	- No event sent.
//	- Oldest timestamp = T1.
//	- T8 is oldest timestamp in most recent timestamps.
//	- In 2 ticks from now: send all events up to T8.
//	- Bigger timestamps than T8 (+) will be sent in future scheduling.
//
// ### Scheduler Tick #2
//
// Incoming events: T7#0, T22#1, T23#2, T20#0, T25#1, T24#2, T21#0
//
// Queues state after insert:
//
//	     [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
//	HEAD    T1  ^        T2  ^        T4  ^
//	        T3  ^        T5  ^        T10
//	        T6  ^        T9           T11
//	        T7  +^       T13          T12
//	        T8  ^        T22 +        T23 +
//	        T20 +        T25 +        T24 +
//	TAIL    T21 +
//
//	- No event sent.
//	- Oldest timestamp = T1.
//	- T21 is oldest timestamp in most recent timestamps.
//	- In 2 ticks from now: send all events up to T21.
//	- T8 is previous oldest timestamp in most recent timestamps.
//	- Next tick: send all events up to T8.
//	- Bigger timestamps than T21 (+) will be sent in future scheduling.
//
// ### Scheduler Tick #3
//
// Incoming events: T30#0, T34#1, T35#2, T31#0, T36#2, T32#0, T37#2, T33#0, T38#2, T50#1, T51#1
//
// Queues state after insert:
//
//	     [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
//	HEAD    T20 ^        T9  ^        T10 ^
//	        T21 ^        T13 ^        T11 ^
//	        T30 +        T22          T12 ^
//	        T31 +        T23          T24
//	        T32 +        T25          T35 +
//	        T33 +        T34 +        T36 +
//	                     T50 +        T37 +
//	 TAIL                T51 +        T38 +
//
//	- Max sent timestamp = T8.
//	- Oldest timestamp = T9.
//	- T33 is oldest timestamp in most recent timestamps.
//	- In 2 ticks from now: send all events up to T33.
//	- T21 is previous oldest timestamp in most recent timestamps.
//	- Next tick: send all events up to T21.
//	- Bigger timestamps than T33 (+) will be sent in future scheduling.
//	-------------------------------------------------------------------
package sorting

import (
	gocontext "context"
	"math"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/types/trace"
)

// The minimum time of delay before sending events forward.
// It should resolve disorders originated from the way syscalls timestamps are taken (about 1ms disorder) and potential
// vCPU sleep (up to 98ms) [source - https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/]
const minDelay = 100 * time.Millisecond
const eventsPassingInterval = 50 * time.Millisecond
const intervalsAmountThresholdForDelay = int(minDelay / eventsPassingInterval)

// EventsChronologicalSorter is an object responsible for sorting arriving events from perf buffer according to their
// chronological order - the time they were invoked in the kernel.
type EventsChronologicalSorter struct {
	cpuEventsQueues                  []cpuEventsQueue // Each CPU has its own events queue because events per CPU arrive in almost chronological order
	outputChanMutex                  sync.Mutex
	extractionSavedTimestamps        []int // Buffer to store timestamps of events for delayed extraction
	errorChan                        chan<- error
	eventsPassingInterval            time.Duration
	intervalsAmountThresholdForDelay int
}

func InitEventSorter() (*EventsChronologicalSorter, error) {
	cpusAmount, err := environment.GetCPUAmount()
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	newSorter := EventsChronologicalSorter{
		cpuEventsQueues:                  make([]cpuEventsQueue, cpusAmount),
		eventsPassingInterval:            eventsPassingInterval,
		intervalsAmountThresholdForDelay: intervalsAmountThresholdForDelay,
	}
	return &newSorter, nil
}

func (sorter *EventsChronologicalSorter) StartPipeline(ctx gocontext.Context, in <-chan *trace.Event, outChanSize int) (
	chan *trace.Event, chan error) {
	out := make(chan *trace.Event, outChanSize)
	errc := make(chan error, 1)
	go sorter.Start(in, out, ctx, errc)
	return out, errc
}

// Start is the main function of the EventsChronologicalSorter class, which orders input events from events channels
// and pass forward all ordered events to the output channel after each interval.
// When exits, the sorter will send forward all buffered events in ordered matter.
func (sorter *EventsChronologicalSorter) Start(in <-chan *trace.Event, out chan<- *trace.Event,
	ctx gocontext.Context, errc chan error) {
	sorter.errorChan = errc
	defer close(out)
	defer close(errc)
	ticker := time.NewTicker(sorter.eventsPassingInterval)
	for {
		select {
		case newEvent := <-in:
			if newEvent == nil {
				sorter.sendEvents(out, math.MaxInt64)
				return
			}
			sorter.addEvent(newEvent)
		case <-ticker.C:
			sorter.updateSavedTimestamps()
			if len(sorter.extractionSavedTimestamps) > sorter.intervalsAmountThresholdForDelay {
				extractionTimestamp := sorter.extractionSavedTimestamps[0]
				sorter.extractionSavedTimestamps = sorter.extractionSavedTimestamps[1:]
				go sorter.sendEvents(out, extractionTimestamp)
			}

		case <-ctx.Done():
			sorter.sendEvents(out, math.MaxInt64)
			return
		}
	}
}

// addEvent add a new event to the appropriate place in queue according to its timestamp
func (sorter *EventsChronologicalSorter) addEvent(newEvent *trace.Event) {
	cq := &sorter.cpuEventsQueues[newEvent.ProcessorID]
	err := cq.InsertByTimestamp(newEvent)
	if err != nil {
		sorter.errorChan <- err
	}
	cq.IsUpdated = true
}

// sendEvents send to output channel all events up to given timestamp
func (sorter *EventsChronologicalSorter) sendEvents(outputChan chan<- *trace.Event, extractionMaxTimestamp int) {
	sorter.outputChanMutex.Lock()
	defer sorter.outputChanMutex.Unlock()
	for {
		mostDelayingQueue, eventTimestamp, err := sorter.getMostDelayingEventCPUQueue()
		if err != nil || eventTimestamp > extractionMaxTimestamp {
			break
		}
		extractionEvent, err := mostDelayingQueue.Get()
		if err != nil {
			sorter.errorChan <- err
			if extractionEvent == nil {
				mostDelayingQueue.Empty()
				continue
			}
		}
		if extractionEvent.Timestamp != eventTimestamp {
			logger.Warnw("Event queue changed while extracting events")
			err := mostDelayingQueue.InsertByTimestamp(extractionEvent)
			if err != nil {
				sorter.errorChan <- err
			}
		} else {
			outputChan <- extractionEvent
		}
	}
}

// updateSavedTimestamps add current most delaying timestamp to saved list
func (sorter *EventsChronologicalSorter) updateSavedTimestamps() {
	mostDelayingLastEventTimestamp, err := sorter.getUpdatedMostDelayedLastCPUEventTimestamp()
	if err != nil { // An error means no new event was received since last update
		// If no CPU was updated, it means that all of the CPUs are fully updated and we can
		// send all cached events received till this moment.
		mostDelayingLastEventTimestamp, err = sorter.getMostRecentEventTimestamp()
		if err != nil {
			if len(sorter.extractionSavedTimestamps) > 0 {
				mostDelayingLastEventTimestamp = sorter.extractionSavedTimestamps[len(sorter.extractionSavedTimestamps)-1]
			} else {
				mostDelayingLastEventTimestamp = 0
			}
		}
	}
	sorter.extractionSavedTimestamps = append(sorter.extractionSavedTimestamps, mostDelayingLastEventTimestamp)
}

// getMostDelayingEventCPUQueue search for the CPU queue which contains the oldest event.
// It also returns the timestamp of its head event, to be used for race condition checks.
// Return nil and timestamp of 0 if no valid queue found.
func (sorter *EventsChronologicalSorter) getMostDelayingEventCPUQueue() (*cpuEventsQueue, int, error) {
	var mostDelayingEventQueue *cpuEventsQueue
	mostDelayingEventQueueHeadTimestamp := 0
	for i := 0; i < len(sorter.cpuEventsQueues); i++ {
		cq := &sorter.cpuEventsQueues[i]
		cqHead := cq.PeekHead()
		if cqHead != nil &&
			(mostDelayingEventQueue == nil ||
				cqHead.Timestamp < mostDelayingEventQueueHeadTimestamp) {
			mostDelayingEventQueue = cq
			mostDelayingEventQueueHeadTimestamp = cqHead.Timestamp
		}
	}
	if mostDelayingEventQueue == nil {
		return nil, 0, errfmt.Errorf("no queue with events found")
	}
	return mostDelayingEventQueue, mostDelayingEventQueueHeadTimestamp, nil
}

// getUpdatedMostDelayedLastCPUEventTimestamp search for the CPU queue with the oldest last inserted event which was updated since
// last check
// Queues which were not updated since last check are ignored to prevent events starvation if a CPU is not active
func (sorter *EventsChronologicalSorter) getUpdatedMostDelayedLastCPUEventTimestamp() (int, error) {
	var newMostDelayedEventTimestamp int
	foundUpdatedQueue := false
	for i := 0; i < len(sorter.cpuEventsQueues); i++ {
		cq := &sorter.cpuEventsQueues[i]
		queueTail := cq.PeekTail()
		if queueTail != nil && cq.IsUpdated &&
			(!foundUpdatedQueue ||
				queueTail.Timestamp < newMostDelayedEventTimestamp) {
			newMostDelayedEventTimestamp = queueTail.Timestamp
			foundUpdatedQueue = true
		}
		cq.IsUpdated = false // Mark that the values of the queue were checked from previous time
	}
	if !foundUpdatedQueue {
		return 0, errfmt.Errorf("no valid CPU events queue was updated since last interval")
	}
	return newMostDelayedEventTimestamp, nil
}

// getMostRecentEventTimestamp get the timestamp of the most recent event received from all CPUs.
func (sorter *EventsChronologicalSorter) getMostRecentEventTimestamp() (int, error) {
	mostRecentEventTimestamp := 0
	for i := 0; i < len(sorter.cpuEventsQueues); i++ {
		cq := &sorter.cpuEventsQueues[i]
		queueTail := cq.PeekTail()
		if queueTail != nil &&
			queueTail.Timestamp > mostRecentEventTimestamp {
			mostRecentEventTimestamp = queueTail.Timestamp
		}
	}
	if mostRecentEventTimestamp == 0 {
		return 0, errfmt.Errorf("all CPU queues are empty")
	}
	return mostRecentEventTimestamp, nil
}
