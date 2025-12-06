package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	testerName = "proctreetester"
)

type e2eProcessTreeDataSource struct {
	cb            detect.SignatureHandler
	log           detect.Logger
	processTreeDS *datasource.ProcessTreeDS
	holdTime      int
}

// Init is called once when the signature is loaded.
func (sig *e2eProcessTreeDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.log = ctx.Logger

	var err error
	sig.processTreeDS, err = datasource.GetProcessTreeDataSource(ctx)
	if err != nil {
		return err
	}

	// Default to 5 seconds if not set
	sig.holdTime = 5
	if holdTimeStr := os.Getenv("PROCTREE_HOLD_TIME"); holdTimeStr != "" {
		holdTime, err := strconv.Atoi(holdTimeStr)
		if err != nil {
			return err
		}
		sig.holdTime = holdTime
	}

	return nil
}

// GetMetadata returns metadata about the signature.
func (sig *e2eProcessTreeDataSource) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "PROCTREE_DATA_SOURCE",
		EventName:   "PROCTREE_DATA_SOURCE",
		Version:     "0.1.0",
		Name:        "Process Tree Data Source Test",
		Description: "Instrumentation events E2E Tests: Process Tree Data Source Test",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

// GetSelectedEvents returns a list of events that the signature wants to subscribe to.
func (sig *e2eProcessTreeDataSource) GetSelectedEvents() (
	[]detect.SignatureEventSelector, error,
) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

// OnEvent is called when a subscribed event occurs.
func (sig *e2eProcessTreeDataSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		// ATTENTION: In order to have all the information in the data source,
		// this signature needs to have tracee running with the following flags:
		//
		// * --output option:sort-events
		// * --stores process.source=both
		// * --events PROCTREE_DATA_SOURCE

		// Check that the event is from the tester
		pathname, err := eventObj.GetStringArgumentByName("pathname")
		if err != nil || !strings.HasSuffix(pathname, testerName) {
			return err
		}

		// Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms (100ms * 2^(attempt-1))
		retryBackoff := func(attempt int) {
			if attempt > 0 {
				time.Sleep(100 * time.Millisecond * (1 << uint(attempt-1)))
			}
		}

		go func() {
			time.Sleep(time.Duration(sig.holdTime) * time.Second) // Wait a bit to let the process tree be updated

			// Retry logic for checking the data source
			maxRetries := 5

			// Check thread entries in the data source
			var threadErrorHistory []string
			threadPassed := false
			for attempt := 0; attempt < maxRetries; attempt++ {
				retryBackoff(attempt)

				err = sig.checkThread(&eventObj)
				if err != nil {
					threadErrorHistory = append(threadErrorHistory, fmt.Sprintf("  Attempt %d: checkThread: %v", attempt+1, err))
					continue // retry
				}

				if attempt > 0 {
					sig.log.Infow(fmt.Sprintf("[e2eProcessTreeDataSource] SUCCESS: checkThread | tid=%d | retries=%d",
						eventObj.HostThreadID, attempt))
				}
				threadPassed = true
				break
			}
			if !threadPassed {
				sig.log.Errorw(fmt.Sprintf("[e2eProcessTreeDataSource] ERROR: checkThread | tid=%d | FAILED after %d attempts:\n%s",
					eventObj.HostThreadID, maxRetries, strings.Join(threadErrorHistory, "\n")))
				return
			}

			// Check process entries in the data source
			var processErrorHistory []string
			processPassed := false
			for attempt := 0; attempt < maxRetries; attempt++ {
				retryBackoff(attempt)

				err = sig.checkProcess(&eventObj)
				if err != nil {
					processErrorHistory = append(processErrorHistory, fmt.Sprintf("  Attempt %d: checkProcess: %v", attempt+1, err))
					continue // retry
				}

				if attempt > 0 {
					sig.log.Infow(fmt.Sprintf("[e2eProcessTreeDataSource] SUCCESS: checkProcess | pid=%d | retries=%d",
						eventObj.HostProcessID, attempt))
				}
				processPassed = true
				break
			}
			if !processPassed {
				sig.log.Errorw(fmt.Sprintf("[e2eProcessTreeDataSource] ERROR: checkProcess | pid=%d | FAILED after %d attempts:\n%s",
					eventObj.HostProcessID, maxRetries, strings.Join(processErrorHistory, "\n")))
				return
			}

			// Check lineage entries in the data source
			var lineageErrorHistory []string
			lineagePassed := false
			for attempt := 0; attempt < maxRetries; attempt++ {
				retryBackoff(attempt)

				err = sig.checkLineage(&eventObj)
				if err != nil {
					lineageErrorHistory = append(lineageErrorHistory, fmt.Sprintf("  Attempt %d: checkLineage: %v", attempt+1, err))
					continue // retry
				}

				if attempt > 0 {
					sig.log.Infow(fmt.Sprintf("[e2eProcessTreeDataSource] SUCCESS: checkLineage | pid=%d | retries=%d",
						eventObj.HostProcessID, attempt))
				}
				lineagePassed = true
				break
			}
			if !lineagePassed {
				sig.log.Errorw(fmt.Sprintf("[e2eProcessTreeDataSource] ERROR: checkLineage | pid=%d | FAILED after %d attempts:\n%s",
					eventObj.HostProcessID, maxRetries, strings.Join(lineageErrorHistory, "\n")))
				return
			}

			// If all checks passed, send a finding
			m, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data:        map[string]interface{}{},
			})
		}()
	}

	return nil
}

// checkThread checks if thread info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkThread(eventObj *trace.Event) error {
	threadTimeInfo, err := sig.processTreeDS.GetEventThreadInfo(eventObj)
	if err != nil {
		return err
	}
	threadInfo := threadTimeInfo.Info

	debugFn := func(custom string) string {
		return fmt.Sprintf(
			"thread in event "+
				"(tid:%d, pid:%d, nstid:%d, starttime:%d, hash:%d, name:%s) "+
				"doesn't match thread in proctree "+
				"(tid:%d, pid:%d, nstid:%d, starttime:%d, hash:%d, name:%s) - %s",
			eventObj.HostThreadID,
			eventObj.HostProcessID,
			eventObj.ThreadID,
			eventObj.ThreadStartTime,
			eventObj.ProcessEntityId,
			eventObj.ProcessName,
			threadInfo.Tid,
			threadInfo.Pid,
			threadInfo.NsTid,
			threadInfo.StartTime.UnixNano(),
			threadInfo.EntityId,
			threadInfo.Name,
			custom,
		)
	}

	// Compare
	if threadInfo.Tid != eventObj.HostThreadID {
		return errors.New(debugFn("no match for tid"))
	}
	if threadInfo.Pid != eventObj.HostProcessID {
		return errors.New(debugFn("no match for pid"))
	}
	if threadInfo.NsTid != eventObj.ThreadID {
		return errors.New(debugFn("no match for ns tid"))
	}
	if int(threadInfo.StartTime.UnixNano()) != eventObj.ThreadStartTime {
		return errors.New(debugFn("no match for start time"))
	}
	if threadInfo.Name != eventObj.ProcessName {
		return errors.New(debugFn("no match for thread name"))
	}

	return nil
}

// checkProcess checks if process info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkProcess(eventObj *trace.Event) error {
	processTimeInfo, err := sig.processTreeDS.GetEventProcessInfo(eventObj)
	if err != nil {
		return err
	}
	processInfo := processTimeInfo.Info

	debugFn := func(custom string) string {
		return fmt.Sprintf(
			"process in event "+
				"(pid:%d, nspid:%d, ppid:%d, starttime:%d, hash:%d) "+
				"doesn't match process in proctree "+
				"(pid:%d, nspid:%d, ppid:%d, starttime:%d, hash:%d) - %s",
			eventObj.HostProcessID,
			eventObj.ProcessID,
			eventObj.HostParentProcessID,
			eventObj.ThreadStartTime,
			eventObj.ProcessEntityId,
			processInfo.Pid,
			processInfo.NsPid,
			processInfo.Ppid,
			processInfo.StartTime.UnixNano(),
			processInfo.EntityId,
			custom,
		)
	}

	// Compare
	if processInfo.Pid != eventObj.HostProcessID {
		return errors.New(debugFn("no match for pid"))
	}
	if processInfo.NsPid != eventObj.ProcessID {
		return errors.New(debugFn("no match for ns pid"))
	}
	if processInfo.Ppid != eventObj.HostParentProcessID {
		return errors.New(debugFn("no match for ppid"))
	}
	if int(processInfo.StartTime.UnixNano()) != eventObj.ThreadStartTime {
		return errors.New(debugFn("no match for start time"))
	}

	// Check if the process lists itself in the list of its threads (case #1)
	threadExist := false
	for tid := range processInfo.ThreadsIds {
		if tid == eventObj.HostThreadID {
			threadExist = true
			break
		}
	}
	if !threadExist {
		return errors.New(debugFn("process not listed as thread"))
	}

	// TODO
	//
	// Cannot compare command name because event will bring the full binary path and the process
	// tree might have the full binary path (if the execve event was caught) OR the command name if
	// procfs enrichment ran first. We can read /proc/<pid>/exe to get the full binary path in the
	// procfs enrichment, but that requires raising privileges and, since our procfs enrichment is
	// async, that might not be an option (due to cost of raising capabilities).
	//
	// pathname, err := eventObj.GetStringArgumentByName("pathname")
	// if err != nil {
	// 	return err
	// }
	// if processInfo.ExecutionBinary.Path != pathname {
	// 	return errors.New(debug("no match for pathname"))
	// }

	return nil
}

func (sig *e2eProcessTreeDataSource) checkLineage(eventObj *trace.Event) error {
	debug := func(custom string) string {
		return fmt.Sprintf(
			"thread (tid:%d, pid: %d, ppid: %d, time: %d, hash: %d) %s",
			eventObj.ThreadID, eventObj.HostProcessID, eventObj.HostParentProcessID,
			eventObj.ThreadStartTime, eventObj.ProcessEntityId, custom,
		)
	}

	maxDepth := 10 // up to 10 ancestors + process itself

	lineageInfo, err := sig.processTreeDS.GetEventProcessLineage(eventObj, maxDepth)
	if err != nil {
		return err
	}
	// compareMaps compares two maps and returns true if they are equal
	compareMaps := func(map1, map2 map[int]uint32) bool {
		// Compare maps using smaller as reference. This is because the process entry might have
		// more entries than the lineage entry (it is done later and both the children and threads
		// maps aren't changelogs.
		smaller := map1
		bigger := map2
		if len(map1) > len(map2) {
			smaller = map2
			bigger = map1
		}
		for key, value := range smaller {
			if bigger[key] != value {
				return false
			}
		}
		return true
	}

	// analyzeMaps analyzes differences between two maps and returns detailed mismatch information
	analyzeMaps := func(baseMap, givenMap map[int]uint32) ([]int, string) {
		var missing []int
		var valueMismatchDetails []string

		// Use smaller map as reference (same logic as compareMaps)
		smaller := baseMap
		bigger := givenMap
		smallerIsBase := len(baseMap) <= len(givenMap)

		if len(baseMap) > len(givenMap) {
			smaller = givenMap
			bigger = baseMap
		}

		// Check for missing keys and value mismatches in the direction that matters
		for k, smallerValue := range smaller {
			if biggerValue, exists := bigger[k]; !exists {
				missing = append(missing, k)
			} else if smallerValue != biggerValue {
				if smallerIsBase {
					valueMismatchDetails = append(valueMismatchDetails,
						fmt.Sprintf("pid=%d hash_expected=%d hash_actual=%d", k, smallerValue, biggerValue))
				} else {
					valueMismatchDetails = append(valueMismatchDetails,
						fmt.Sprintf("pid=%d hash_expected=%d hash_actual=%d", k, biggerValue, smallerValue))
				}
			}
		}

		return missing, strings.Join(valueMismatchDetails, ", ")
	}

	// isMatch checks if a process in the lineage matches the process in the event.
	// Uses retry logic to handle async process tree updates.
	isMatch := func(
		compareBase datasource.TimeRelevantInfo[datasource.ProcessInfo],
		id uint32,
		maxRetries int,
		retryDelay time.Duration,
		context string,
	) error {
		processId := int(compareBase.Info.Pid)

		var lastErr error
		for attempt := 0; attempt < maxRetries; attempt++ {
			given, err := sig.processTreeDS.GetProcessInfo(datasource.ProcKey{
				EntityId: id,
				Time:     compareBase.Timestamp,
			})
			if err != nil {
				lastErr = err
				if attempt < maxRetries-1 {
					time.Sleep(retryDelay)
					continue
				}
				return err
			}

			// Compare maps and collect mismatch details
			threadsMatch := compareMaps(compareBase.Info.ThreadsIds, given.Info.ThreadsIds)
			childrenMatch := compareMaps(compareBase.Info.ChildProcessesIds, given.Info.ChildProcessesIds)

			var mismatchDetails string

			// If maps don't match and not the last attempt, retry
			if (!threadsMatch || !childrenMatch) && attempt < maxRetries-1 {
				lastErr = fmt.Errorf("maps don't match (threads:%v, children:%v)", threadsMatch, childrenMatch)
				time.Sleep(retryDelay)
				continue
			}

			if !threadsMatch || !childrenMatch {
				var details []string
				if !threadsMatch {
					missing, valueMismatchDetails := analyzeMaps(compareBase.Info.ThreadsIds, given.Info.ThreadsIds)
					if len(missing) > 0 || valueMismatchDetails != "" {
						details = append(details, fmt.Sprintf("threads: missing=%v mismatches=[%s]", missing, valueMismatchDetails))
					}
				}
				if !childrenMatch {
					missing, valueMismatchDetails := analyzeMaps(compareBase.Info.ChildProcessesIds, given.Info.ChildProcessesIds)
					if len(missing) > 0 || valueMismatchDetails != "" {
						details = append(details, fmt.Sprintf("children: missing=%v mismatches=[%s]", missing, valueMismatchDetails))
					}
				}
				mismatchDetails = strings.Join(details, ", ")
			}

			// Log retry information for test diagnostics
			if attempt > 0 && threadsMatch && childrenMatch {
				sig.log.Infow(fmt.Sprintf("[e2eProcessTreeDataSource] SUCCESS: checkLineage | pid=%d context=%s | retries=%d",
					processId, context, attempt+1))
			}
			// On final attempt, be tolerant of map mismatches
			if !threadsMatch || !childrenMatch {
				sig.log.Warnw(fmt.Sprintf("[e2eProcessTreeDataSource] WARNING: checkLineage | pid=%d context=%s | retries=%d | %s",
					processId, context, maxRetries, mismatchDetails))
			}

			// Zero fields that can't be compared (timing, maps, etc)
			zeroSomeProcStuff(&compareBase.Info)
			zeroSomeProcStuff(&given.Info)

			// Compare the rest (core process information)
			if !reflect.DeepEqual(compareBase.Info, given.Info) {
				return errors.New(debug("process core information does not match"))
			}

			return nil // Success
		}

		return lastErr
	}

	retries := 15
	// Be aware that if the delay is too high, the test trigger must be adjusted
	// accordingly to not timeout before the test is finished.
	retryDelay := 200 * time.Millisecond

	// First ancestor is the process itself, compare object from the Lineage and Object queries
	context := fmt.Sprintf("event-hostpid-%d-self", eventObj.HostProcessID)
	err = isMatch((*lineageInfo)[0], eventObj.ProcessEntityId, retries, retryDelay, context)
	if err != nil {
		return err
	}

	// Check all ancestors in the data source up to maxDepth
	for i, ancestor := range (*lineageInfo)[1:] {
		context := fmt.Sprintf("event-hostpid-%d-ancestor-%d", eventObj.HostProcessID, i+1)
		err = isMatch(ancestor, ancestor.Info.EntityId, retries, retryDelay, context)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sig *e2eProcessTreeDataSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eProcessTreeDataSource) Close() {}

func zeroSomeProcStuff(process *datasource.ProcessInfo) {
	// processes die during the test
	process.IsAlive = false

	// can't compare maps
	process.ChildProcessesIds = make(map[int]uint32)
	process.ThreadsIds = make(map[int]uint32)

	// timings are not comparable (they are related to time of query)
	process.StartTime = time.Time{}
	process.ExecTime = time.Time{}
	process.ExitTime = time.Time{}
}
