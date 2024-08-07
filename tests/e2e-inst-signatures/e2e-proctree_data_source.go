package main

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

var firstEventWait = sync.Once{}

const (
	testerName = "proctreetester"
	version    = 1
)

type e2eProcessTreeDataSource struct {
	cb            detect.SignatureHandler
	processTreeDS *helpers.ProcessTreeDS
}

var e2eProcessTreeDataSourceMetadata = detect.SignatureMetadata{
	ID:          "PROCTREE_DATA_SOURCE",
	EventName:   "PROCTREE_DATA_SOURCE",
	Version:     "0.1.0",
	Name:        "Process Tree Data Source Test",
	Description: "Instrumentation events E2E Tests: Process Tree Data Source Test",
	Tags:        []string{"e2e", "instrumentation"},
}

// Init is called once when the signature is loaded.
func (sig *e2eProcessTreeDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	var err error
	sig.processTreeDS, err = helpers.GetProcessTreeDataSource(ctx)
	if err != nil {
		return err
	}

	return nil
}

// GetMetadata returns metadata about the signature.
func (sig *e2eProcessTreeDataSource) GetMetadata() (detect.SignatureMetadata, error) {
	return e2eProcessTreeDataSourceMetadata, nil
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
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		// ATTENTION: In order to have all the information in the data source, this signature needs
		// that tracee is running with the following flags:
		//
		// * --output option:sort-events
		// * --proctree source=both
		// * --events PROCTREE_DATA_SOURCE
		//
		// With that, all cases, but the lineage test, work. The lineage test requires ancestor
		// history, so the signature test needs to let process tree to enrich and populate all
		// entries for a moment (sleeping a bit during signature initialization is enough).
		// The reason why the sleep isn't at the signature init function is because that would
		// stop all other signatures to be loaded on time and make other tests to fail.
		//
		firstEventWait.Do(func() {
			time.Sleep(15 * time.Second)
		})

		// Check that the event is from the tester
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil || !strings.HasSuffix(pathname, testerName) {
			return err
		}
		// Check thread entries in the data source
		err = sig.checkThread(&eventObj)
		if err != nil {
			return err
		}
		// Check process entries in the data source
		err = sig.checkProcess(&eventObj)
		if err != nil {
			return err
		}
		// Check lineage entries in the data source
		err = sig.checkLineage(&eventObj)
		if err != nil {
			return err
		}
		// If all checks passed, send a finding
		m, _ := sig.GetMetadata()
		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

// checkThread checks if thread info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkThread(eventObj *trace.Event) error {
	threadTimeInfo, err := sig.processTreeDS.GetEventThreadInfo(eventObj)
	if err != nil {
		return err
	}
	queryTime := time.Unix(0, int64(eventObj.Timestamp))
	threadInfo := threadTimeInfo.Info

	debug := func(custom string) string {
		return fmt.Sprintf(
			"thread in event (tid:%d, pid: %d, ppid: %d, time: %d, hash: %d, name: %s) doesn't "+
				"match thread in proctree (tid:%d, pid: %d, time: %d, hash: %d, "+
				"name: %s) - %s",
			eventObj.ThreadID, eventObj.HostProcessID, eventObj.HostParentProcessID,
			eventObj.ThreadStartTime, eventObj.ProcessEntityId, eventObj.ProcessName,
			threadInfo.Tid, threadInfo.Pid, threadInfo.StartTime.UnixNano(), threadInfo.EntityId,
			threadInfo.Name,
			custom,
		)
	}

	// Compare TID, NS TID and PID
	if threadInfo.Tid != eventObj.HostThreadID {
		return fmt.Errorf(debug("no match for tid"))
	}
	if threadInfo.NsTid != eventObj.ThreadID {
		return fmt.Errorf(debug("no match for ns tid"))
	}
	if threadInfo.Pid != eventObj.HostProcessID {
		return fmt.Errorf(debug("no match for pid"))
	}
	if threadTimeInfo.Timestamp != queryTime {
		return fmt.Errorf(debug("no match for info timestamp"))
	}
	if threadInfo.Name != eventObj.ProcessName {
		return fmt.Errorf(debug("no match for thread name"))
	}

	return nil
}

// checkProcess checks if process info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkProcess(eventObj *trace.Event) error {
	processTimeInfo, err := sig.processTreeDS.GetEventProcessInfo(eventObj)
	if err != nil {
		return err
	}
	queryTime := time.Unix(0, int64(eventObj.Timestamp))
	processInfo := processTimeInfo.Info

	debug := func(custom string) string {
		return fmt.Sprintf(
			"process in event (tid: %d pid: %d, ppid: %d, time: %d, hash: %d) "+
				"doesn't match process in proctree (pid: %d, ppid: %d, hash: %d) - %s",
			eventObj.ThreadID, eventObj.HostProcessID, eventObj.HostParentProcessID,
			eventObj.ThreadStartTime, eventObj.ProcessEntityId,
			processInfo.Pid, processInfo.Ppid, processInfo.EntityId,
			custom,
		)
	}

	// Compare PID, NS PID and PPID
	if processInfo.Pid != eventObj.HostProcessID {
		return fmt.Errorf(debug("no match for pid"))
	}
	if processInfo.NsPid != eventObj.ProcessID {
		return fmt.Errorf(debug("no match for ns pid"))
	}
	if processInfo.Ppid != eventObj.HostParentProcessID {
		return fmt.Errorf(debug("no match for ppid"))
	}
	if processTimeInfo.Timestamp != queryTime {
		return fmt.Errorf(debug("no match for timestamp"))
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
		return fmt.Errorf(debug("process not listed as thread"))
	}

	// TODO
	//
	// Cannot compare command name because event will bring the full binary path and the process
	// tree might have the full binary path (if the execve event was caught) OR the command name if
	// procfs enrichment ran first. We can read /proc/<pid>/exe to get the full binary path in the
	// procfs enrichment, but that requires raising privileges and, since our procfs enrichment is
	// async, that might not be an option (due to cost of raising capabilities).
	//
	// pathname, err := helpers.GetTraceeStringArgumentByName(*eventObj, "pathname")
	// if err != nil {
	// 	return err
	// }
	// if processInfo.ExecutionBinary.Path != pathname {
	// 	return fmt.Errorf(debug("no match for pathname"))
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

	maxDepth := 5 // up to 5 ancestors + process itself

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

	// doesItMatch checks if a process in the lineage matches the process in the event.
	doesItMatch := func(compareBase datasource.TimeRelevantInfo[datasource.ProcessInfo], id uint32) error {
		given, err := sig.processTreeDS.GetProcessInfo(datasource.ProcKey{
			EntityId: id,
			Time:     compareBase.Timestamp,
		})
		if err != nil {
			return err
		}

		// Debug (TODO: remove this after proctree is stable)
		//
		// fmt.Printf("=> base (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
		// 	compareBase.Info.Pid, compareBase.Info.Ppid, compareBase.Info.ExecTime, compareBase.Info.EntityId,
		// 	compareBase.Info.Cmd, compareBase.Info.ExecutionBinary.Path,
		// )
		// fmt.Printf("=> given (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
		// 	given.Info.Pid, given.Info.Ppid, given.Info.ExecTime, given.Info.EntityId,
		// 	given.Info.Cmd, given.Info.ExecutionBinary.Path,
		// )

		// Compare
		if !compareMaps(compareBase.Info.ThreadsIds, given.Info.ThreadsIds) {
			return fmt.Errorf(debug("threads do not match"))
		}
		if !compareMaps(compareBase.Info.ChildProcessesIds, given.Info.ChildProcessesIds) {
			return fmt.Errorf(debug("children do not match"))
		}

		// Zero fields that can't be compared (timing, maps, etc)
		zeroSomeProcStuff(&compareBase.Info)
		zeroSomeProcStuff(&given.Info)

		// Compare the rest
		if !reflect.DeepEqual(compareBase.Info, given.Info) {
			fmt.Printf("%+v\n", compareBase.Info)
			fmt.Printf("%+v\n", given.Info)
			// fmt.Printf("=> base (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
			// compareBase.Info.Pid, compareBase.Info.Ppid, compareBase.Info.ExecTime, compareBase.Info.EntityId,
			// compareBase.Info.Cmd, compareBase.Info.ExecutionBinary.Path,
			// )
			// fmt.Printf("=> given (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
			// given.Info.Pid, given.Info.Ppid, given.Info.ExecTime, given.Info.EntityId,
			// given.Info.Cmd, given.Info.ExecutionBinary.Path,
			// )
			return fmt.Errorf(debug("process in lineage does not match"))
		}

		return nil
	}

	// First ancestor is the process itself, compare object from the Lineage and Object queries
	err = doesItMatch((*lineageInfo)[0], eventObj.ProcessEntityId)
	if err != nil {
		return err
	}

	// Check all ancestors in the data source up to maxDepth
	for _, ancestor := range (*lineageInfo)[1:] {
		err = doesItMatch(ancestor, ancestor.Info.EntityId) // compare lineage with proc from datasource
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
