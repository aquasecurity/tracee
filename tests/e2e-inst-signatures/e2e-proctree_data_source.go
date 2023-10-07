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
	processTreeDS detect.DataSource
}

// Init is called once when the signature is loaded.
func (sig *e2eProcessTreeDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
	if !ok {
		return fmt.Errorf("data source tracee/process_tree is not registered")
	}

	if processTreeDataSource.Version() > 1 {
		return fmt.Errorf(
			"data source tracee/process_tree version %d is not supported",
			processTreeDataSource.Version(),
		)
	}

	sig.processTreeDS = processTreeDataSource

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
		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

// checkThread checks if thread info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkThread(eventObj *trace.Event) error {
	debug := func(custom string) string {
		return fmt.Sprintf(
			"thread (tid:%d, pid: %d, ppid: %d, time: %d, hash: %d) %s",
			eventObj.ThreadID, eventObj.HostProcessID, eventObj.HostParentProcessID,
			eventObj.ThreadStartTime, eventObj.ProcessEntityId, custom,
		)
	}

	// Pick the thread info from the data source
	threadQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ThreadKey{
			EntityId: eventObj.ThreadEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
		},
	)
	if err != nil {
		return fmt.Errorf(debug("could not find thread"))
	}
	threadInfo, ok := threadQueryAnswer["thread_info"].(datasource.ThreadInfo)
	if !ok {
		return fmt.Errorf(debug("could not extract info"))
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

	return nil
}

// checkProcess checks if process info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkProcess(eventObj *trace.Event) error {
	debug := func(custom string) string {
		return fmt.Sprintf(
			"process (tid: %d pid: %d, ppid: %d, time: %d, hash: %d) %s",
			eventObj.ThreadID, eventObj.HostProcessID, eventObj.HostParentProcessID,
			eventObj.ThreadStartTime, eventObj.ProcessEntityId, custom,
		)
	}

	// Pick the process info from the data source
	procQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ProcKey{
			EntityId: eventObj.ProcessEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
		})
	if err != nil {
		return fmt.Errorf(debug("could not find process"))
	}
	processInfo, ok := procQueryAnswer["process_info"].(datasource.ProcessInfo)
	if !ok {
		return fmt.Errorf(debug("could not extract info"))
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

	// Pick the lineage info from the data source.
	lineageQueryAnswer, err := sig.processTreeDS.Get(
		datasource.LineageKey{
			EntityId: eventObj.ProcessEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
			MaxDepth: maxDepth,
		},
	)
	if err != nil {
		return fmt.Errorf(debug("could not find lineage"))
	}
	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
	if !ok {
		return fmt.Errorf("failed to extract ProcessLineage from data")
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

	// pickProcessFromDS picks a process from the data source.
	pickProcessFromDS := func(id uint32) (datasource.ProcessInfo, error) {
		processQueryAnswer, err := sig.processTreeDS.Get(
			datasource.ProcKey{
				EntityId: id,
				Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
			},
		)
		if err != nil {
			return datasource.ProcessInfo{}, fmt.Errorf(debug("could not find process"))
		}
		given, ok := processQueryAnswer["process_info"].(datasource.ProcessInfo)
		if !ok {
			return datasource.ProcessInfo{}, fmt.Errorf(debug("could not extract info"))
		}
		return given, nil
	}

	// doesItMatch checks if a process in the lineage matches the process in the event.
	doesItMatch := func(compareBase datasource.ProcessInfo, id uint32) error {
		_, err = sig.processTreeDS.Get(
			datasource.ProcKey{
				EntityId: compareBase.EntityId,
				Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
			},
		)
		if err != nil {
			return fmt.Errorf(debug("could not find process"))
		}
		given, err := pickProcessFromDS(id)
		if err != nil {
			return err
		}

		// Debug (TODO: remove this after proctree is stable)
		//
		// fmt.Printf("=> base (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
		// 	compareBase.Pid, compareBase.Ppid, compareBase.ExecTime, compareBase.EntityId,
		// 	compareBase.Cmd, compareBase.ExecutionBinary.Path,
		// )
		// fmt.Printf("=> given (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
		// 	given.Pid, given.Ppid, given.ExecTime, given.EntityId,
		// 	given.Cmd, given.ExecutionBinary.Path,
		// )

		// Compare
		if !compareMaps(compareBase.ThreadsIds, given.ThreadsIds) {
			return fmt.Errorf(debug("threads do not match"))
		}
		if !compareMaps(compareBase.ChildProcessesIds, given.ChildProcessesIds) {
			return fmt.Errorf(debug("children do not match"))
		}

		// Zero fields that can't be compared (timing, maps, etc)
		zeroSomeStuff(&compareBase)
		zeroSomeStuff(&given)

		// Compare the rest
		if !reflect.DeepEqual(compareBase, given) {
			fmt.Printf("%+v\n", compareBase)
			fmt.Printf("%+v\n", given)
			// fmt.Printf("=> base (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
			// compareBase.Pid, compareBase.Ppid, compareBase.ExecTime, compareBase.EntityId,
			// compareBase.Cmd, compareBase.ExecutionBinary.Path,
			// )
			// fmt.Printf("=> given (pid: %v, ppid: %v, time: %v, hash: %v) (%v) %v\n",
			// given.Pid, given.Ppid, given.ExecTime, given.EntityId,
			// given.Cmd, given.ExecutionBinary.Path,
			// )
			return fmt.Errorf(debug("process in lineage does not match"))
		}

		return nil
	}

	// First ancestor is the process itself, compare object from the Lineage and Object queries
	err = doesItMatch(lineageInfo[0], eventObj.ProcessEntityId)
	if err != nil {
		return err
	}

	// Check all ancestors in the data source up to maxDepth
	for _, ancestor := range lineageInfo[1:] {
		err = doesItMatch(ancestor, ancestor.EntityId) // compare lineage with proc from datasource
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

func zeroSomeStuff(process *datasource.ProcessInfo) {
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
