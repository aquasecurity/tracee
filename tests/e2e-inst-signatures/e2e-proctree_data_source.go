package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	bashPath  = "/usr/bin/bash"
	sleepPath = "/usr/bin/sleep"
	lsPath    = "/usr/bin/ls"
)

type e2eProcessTreeDataSource struct {
	cb            detect.SignatureHandler
	processTreeDS detect.DataSource
}

func (sig *e2eProcessTreeDataSource) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
	if !ok {
		return fmt.Errorf("process tree data source not registered")
	}
	if processTreeDataSource.Version() > 1 {
		return fmt.Errorf("process tree data source version not supported, please update this signature")
	}
	sig.processTreeDS = processTreeDataSource
	return nil
}

func (sig *e2eProcessTreeDataSource) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "PROCESS_TREE_DATA_SOURCE",
		EventName:   "PROCESS_TREE_DATA_SOURCE",
		Version:     "0.1.0",
		Name:        "Process Tree Data Source Test",
		Description: "Instrumentation events E2E Tests: Process Tree Data Source Test",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eProcessTreeDataSource) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

func (sig *e2eProcessTreeDataSource) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		// Check that this is the execution of the test
		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil || !strings.HasSuffix(pathname, lsPath) {
			return err
		}

		err = sig.checkThread(&eventObj)
		if err != nil {
			return err
		}

		err = sig.checkProcess(&eventObj)
		if err != nil {
			return err
		}

		err = sig.checkLineage(&eventObj)
		if err != nil {
			return err
		}

		m, _ := sig.GetMetadata()

		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

// checkThread check that all the information from the event matches the information in
// the process tree
func (sig *e2eProcessTreeDataSource) checkThread(eventObj *trace.Event) error {
	threadQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ThreadKey{
			EntityId: eventObj.ThreadEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
		})
	if err != nil {
		return fmt.Errorf("failed to find thread (tid %d, time %d hash %d) in data source: %v", eventObj.HostThreadID, eventObj.ThreadStartTime, eventObj.ThreadEntityId, err)
	}

	threadInfo, ok := threadQueryAnswer["thread_info"].(datasource.ThreadInfo)
	if !ok {
		return fmt.Errorf("failed to extract ThreadInfo from data")
	}

	// Check IDs
	if threadInfo.Tid != eventObj.HostThreadID {
		return fmt.Errorf("thread info TID in data source (%d) did not match TID from event (%d)",
			threadInfo.Tid, eventObj.HostThreadID)
	}

	if threadInfo.NsTid != eventObj.ThreadID {
		return fmt.Errorf("thread info NS TID in data source (%d) did not match NS TID from event (%d)",
			threadInfo.NsTid, eventObj.ThreadID)
	}

	if threadInfo.Pid != eventObj.HostProcessID {
		return fmt.Errorf("thread info PID in data source (%d) did not match PID from event (%d)",
			threadInfo.Pid, eventObj.HostProcessID)
	}

	// Check thread information
	if threadInfo.Name != eventObj.ProcessName {
		return fmt.Errorf("thread info thread name in data source (%s) did not match known name from event (%s)",
			threadInfo.Name, eventObj.ProcessName)
	}
	return nil
}

// checkProcess check that the information of the process in this point of time (after
// execution) which we can know from the exec event matches the information of the tree
// (which should process the information before it get to this signature)
func (sig *e2eProcessTreeDataSource) checkProcess(eventObj *trace.Event) error {
	procQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ProcKey{
			EntityId: eventObj.ProcessEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
		})
	if err != nil {
		return fmt.Errorf("failed to find process in data source: %v", err)
	}

	processInfo, ok := procQueryAnswer["process_info"].(datasource.ProcessInfo)
	if !ok {
		return fmt.Errorf("failed to extract ProcessInfo from data")
	}

	// Check IDs
	if processInfo.Pid != eventObj.HostProcessID {
		return fmt.Errorf("process info PID in data source (%d) did not match PID from event (%d)",
			processInfo.Pid, eventObj.HostProcessID)
	}

	if processInfo.NsPid != eventObj.ProcessID {
		return fmt.Errorf("process info NS PID in data source (%d) did not match NS PID from event (%d)",
			processInfo.NsPid, eventObj.ProcessID)
	}

	if processInfo.Ppid != eventObj.HostParentProcessID {
		return fmt.Errorf("process info PPID in data source (%d) did not match PPID from event (%d)",
			processInfo.Ppid, eventObj.HostParentProcessID)
	}

	threadExist := false
	for tid := range processInfo.ThreadsIds {
		if tid == eventObj.HostThreadID {
			threadExist = true
			break
		}
	}
	if !threadExist {
		return fmt.Errorf("process info existing threads (%v) doesn't record current thread (%d)",
			processInfo.ThreadsIds, eventObj.HostThreadID)
	}

	// Check execution information
	pathname, err := helpers.GetTraceeStringArgumentByName(*eventObj, "pathname")
	if err != nil {
		return err
	}

	if processInfo.ExecutionBinary.Path != pathname {
		return fmt.Errorf("process info execution binary in data source (%s) did not match known info from event (%s)",
			processInfo.ExecutionBinary.Path, pathname)
	}
	return nil
}

// checkLineage check that the lineage from the tree matches the information we know from the
// bash script that ran.
func (sig *e2eProcessTreeDataSource) checkLineage(eventObj *trace.Event) error {
	// For the check we need only the parent and grandparent (which are created by the test
	// script)
	maxDepth := 2
	lineageQueryAnswer, err := sig.processTreeDS.Get(
		datasource.LineageKey{
			EntityId: eventObj.ProcessEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
			MaxDepth: maxDepth,
		})
	if err != nil {
		return fmt.Errorf("failed to find lineage in data source: %v", err)
	}

	// We want to check things from the lineage against the process query
	procQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ProcKey{
			EntityId: eventObj.ProcessEntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
		})
	if err != nil {
		return fmt.Errorf("failed to find process in data source: %v", err)
	}

	processInfo, ok := procQueryAnswer["process_info"].(datasource.ProcessInfo)
	if !ok {
		return fmt.Errorf("failed to extract ProcessInfo from data")
	}

	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
	if !ok {
		return fmt.Errorf("failed to extract ProcessLineage from data")
	}
	expectedLineageLen := maxDepth + 1 // We expect to get all requested ancestors, and the process itself
	if len(lineageInfo) != expectedLineageLen {
		return fmt.Errorf("missing some ancestors. Expected legacy of %d processes, got %d", expectedLineageLen, len(lineageInfo))
	}
	proc := lineageInfo[0]
	if !reflect.DeepEqual(proc, processInfo) {
		return fmt.Errorf("process in lineage doesn't match process from direct query")
	}

	parent := lineageInfo[1]
	if parent.ExecutionBinary.Path != bashPath {
		return fmt.Errorf("parent process binary path in data source lineage (%s) doesn't match expected (%s)", parent.ExecutionBinary.Path, bashPath)
	}

	grandParent := lineageInfo[2]
	if !strings.Contains(grandParent.ExecutionBinary.Path, "python") {
		return fmt.Errorf("grand parent process binary path in data source lineage (%s) doesn't match expected (%s)", grandParent.ExecutionBinary.Path, "python path")
	}

	threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", grandParent.Pid))
	if err != nil {
		return err
	}
	if len(grandParent.ThreadsIds) != len(threads) {
		return fmt.Errorf("grand parent process threads amount in data source lineage (%d) doesn't match expected (%d)", len(grandParent.ThreadsIds), len(threads))
	}

	// Check grandparent info now, which should have changed upon execution of sleep (the
	// information in the lineage matches the information upon execution of the parent)
	parentProcQueryAnswer, err := sig.processTreeDS.Get(
		datasource.ProcKey{
			EntityId: grandParent.EntityId,
			Time:     time.Unix(0, int64(eventObj.Timestamp)),
		})
	if err != nil {
		return fmt.Errorf("failed to find process in data source: %v", err)
	}

	parentCurrentInfo, ok := parentProcQueryAnswer["process_info"].(datasource.ProcessInfo)
	if !ok {
		return fmt.Errorf("failed to extract ProcessInfo from data of grand parent query")
	}

	if parentCurrentInfo.ExecutionBinary.Path != sleepPath {
		return fmt.Errorf("grand parent process binary path in data source (%s) doesn't match expected (%s)", parentCurrentInfo.ExecutionBinary.Path, sleepPath)
	}
	return nil
}

func (sig *e2eProcessTreeDataSource) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eProcessTreeDataSource) Close() {}
